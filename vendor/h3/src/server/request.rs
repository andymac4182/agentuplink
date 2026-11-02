use std::{convert::TryFrom, sync::Arc};

use bytes::Buf;
use http::{Request, StatusCode};

#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    connection::{self},
    error::{
        connection_error_creators::{CloseStream, HandleFrameStreamErrorOnRequestStream},
        internal_error::InternalConnectionError,
        Code, StreamError,
    },
    frame::{FrameStream, FrameStreamError},
    proto::{
        frame::{Frame, PayloadLen},
        headers::Header,
    },
    qpack,
    quic::{self, SendStream},
    shared_state::{ConnectionState, SharedState},
};

use super::{connection::RequestEnd, stream::RequestStream};

/// Helper struct to await the request headers and return a `Request` object
pub struct RequestResolver<C, B>
where
    C: quic::Connection<B>,
    C::BidiStream: quic::SendStream<B>,
    B: Buf,
{
    #[doc(hidden)]
    // TODO: make this private
    pub frame_stream: FrameStream<C::BidiStream, B>,
    pub(super) request_end: Arc<RequestEnd>,
    pub(super) send_grease_frame: bool,
    pub(super) max_field_section_size: u64,
    pub(super) shared: Arc<SharedState>,
}

// These guards are opt-in: existing resolve_request callers retain their API.
// Construct the first guard before returning the future, so even an unpolled
// future releases the request with a reset instead of an empty response FIN.
struct RejectResolverOnDrop<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    resolver: Option<RequestResolver<C, B>>,
    error_code: Code,
}

impl<C, B> Drop for RejectResolverOnDrop<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn drop(&mut self) {
        if let Some(resolver) = self.resolver.take() {
            resolver.reject(self.error_code);
        }
    }
}

struct RejectResolvedOnDrop<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    stream: Option<RequestStream<C::BidiStream, B>>,
    error_code: Code,
}

impl<C, B> Drop for RejectResolvedOnDrop<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn drop(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.stop_stream(self.error_code);
            stream.stop_sending(self.error_code);
        }
    }
}

impl<C, B> ConnectionState for RequestResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

impl<C, B> CloseStream for RequestResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
}

impl<C, B> RequestResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Reject this request without resolving its headers or dispatching it.
    /// Resets both stream directions and releases its ongoing-request entry.
    pub fn reject(mut self, error_code: Code) {
        self.frame_stream.reset(error_code.value());
        self.frame_stream.stop_sending(error_code);
    }

    /// Resolve the request, resetting it with `error_code` if the returned
    /// future is dropped before completion, including before its first poll.
    /// Use `H3_REQUEST_REJECTED` only before application dispatch. Normal
    /// successful resolution transfers ownership to the returned stream;
    /// ordinary resolution errors retain their original error classification.
    pub fn resolve_request_with_rejection_on_cancel(
        self,
        error_code: Code,
    ) -> impl std::future::Future<
        Output = Result<(Request<()>, RequestStream<C::BidiStream, B>), StreamError>,
    > {
        let mut unresolved = RejectResolverOnDrop {
            resolver: Some(self),
            error_code,
        };
        async move {
            let frame = std::future::poll_fn(|cx| {
                unresolved
                    .resolver
                    .as_mut()
                    .expect("resolver retained until header frame completes")
                    .frame_stream
                    .poll_next(cx)
            })
            .await;
            let resolver = unresolved
                .resolver
                .take()
                .expect("resolver retained until header frame completes");
            let ResolvedRequest {
                request_stream,
                decoded,
                max_field_section_size,
            } = resolver.accept_with_frame(frame)?;
            let mut resolved = RejectResolvedOnDrop::<C, B> {
                stream: Some(request_stream),
                error_code,
            };
            let result = ResolvedRequest::<C, B>::resolve_parts(
                resolved
                    .stream
                    .as_mut()
                    .expect("stream retained during resolution"),
                decoded,
                max_field_section_size,
            )
            .await;
            // Disarm on both success and an ordinary error: cancellation
            // cleanup must not rewrite a malformed-request/protocol error.
            let stream = resolved
                .stream
                .take()
                .expect("stream retained during resolution");
            result.map(|request| (request, stream))
        }
    }

    /// Returns a future to await the request headers and return a `Request` object
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn resolve_request(
        mut self,
    ) -> Result<(Request<()>, RequestStream<C::BidiStream, B>), StreamError> {
        let frame = std::future::poll_fn(|cx| self.frame_stream.poll_next(cx)).await;
        let req = self.accept_with_frame(frame)?;
        Ok(req.resolve().await?)
    }

    /// Accepts a http request where the first frame has already been read and decoded.
    ///
    /// This is needed as a bidirectional stream may be read as part of incoming webtransport
    /// bi-streams. If it turns out that the stream is *not* a `WEBTRANSPORT_STREAM` the request
    /// may still want to be handled and passed to the user.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn accept_with_frame(
        mut self,
        frame: Result<Option<Frame<PayloadLen>>, FrameStreamError>,
    ) -> Result<ResolvedRequest<C, B>, StreamError> {
        let mut encoded = match frame {
            Ok(Some(Frame::Headers(h))) => h,

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# If a client-initiated
            //# stream terminates without enough of the HTTP message to provide a
            //# complete response, the server SHOULD abort its response stream with
            //# the error code H3_REQUEST_INCOMPLETE.
            Ok(None) => {
                self.frame_stream.reset(Code::H3_REQUEST_INCOMPLETE.value());
                return Err(StreamError::StreamError {
                    code: Code::H3_REQUEST_INCOMPLETE,
                    reason: "stream terminated without headers".to_string(),
                });
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A server MUST treat the
            //# receipt of a PUSH_PROMISE frame as a connection error of type
            //# H3_FRAME_UNEXPECTED.
            Ok(Some(_)) => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED.
                // Close if the first frame is not a header frame
                return Err(
                    self.handle_connection_error_on_stream(InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        "first request frame is not headers".to_string(),
                    )),
                );
            }
            Err(e) => {
                return Err(self.handle_frame_stream_error_on_request_stream(e));
            }
        };

        let decoded = match qpack::decode_stateless(&mut encoded, self.max_field_section_size) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
            //# An HTTP/3 implementation MAY impose a limit on the maximum size of
            //# the message header it will accept on an individual HTTP message.
            Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => Err(cancel_size),
            Ok(decoded) => Ok(decoded),
            Err(_e) => {
                return Err(
                    self.handle_connection_error_on_stream(InternalConnectionError {
                        code: Code::QPACK_DECOMPRESSION_FAILED,
                        message: "Failed to decode headers".to_string(),
                    }),
                );
            }
        };

        let request_stream = RequestStream {
            request_end: self.request_end,
            inner: connection::RequestStream::new(
                self.frame_stream,
                self.max_field_section_size,
                self.shared.clone(),
                self.send_grease_frame,
            ),
        };

        Ok(ResolvedRequest::new(
            request_stream,
            decoded,
            self.max_field_section_size,
        ))
    }
}

pub struct ResolvedRequest<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    request_stream: RequestStream<C::BidiStream, B>,
    // Ok or `REQUEST_HEADER_FIELDS_TO_LARGE` which needs to be sent
    decoded: Result<qpack::Decoded, u64>,
    max_field_section_size: u64,
}

impl<B, C> ResolvedRequest<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    pub fn new(
        request_stream: RequestStream<C::BidiStream, B>,
        decoded: Result<qpack::Decoded, u64>,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            request_stream,
            decoded,
            max_field_section_size,
        }
    }

    /// Finishes the resolution of the request
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn resolve(
        mut self,
    ) -> Result<(Request<()>, RequestStream<C::BidiStream, B>), StreamError> {
        let request = Self::resolve_parts(
            &mut self.request_stream,
            self.decoded,
            self.max_field_section_size,
        )
        .await?;
        Ok((request, self.request_stream))
    }

    async fn resolve_parts(
        request_stream: &mut RequestStream<C::BidiStream, B>,
        decoded: Result<qpack::Decoded, u64>,
        max_field_section_size: u64,
    ) -> Result<Request<()>, StreamError> {
        let fields = match decoded {
            Ok(v) => v.fields,
            Err(cancel_size) => {
                // Send and await the error response
                request_stream
                    .send_response(
                        http::Response::builder()
                            .status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
                            .body(())
                            .expect("header too big response"),
                    )
                    .await?;

                return Err(StreamError::HeaderTooBig {
                    actual_size: cancel_size,
                    max_size: max_field_section_size,
                });
            }
        };

        // Parse the request headers
        let result = match Header::try_from(fields) {
            Ok(header) => match header.into_request_parts() {
                Ok(parts) => Ok(parts),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };
        let (method, uri, protocol, headers) = match result {
            Ok(parts) => parts,
            Err(err) => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
                //# Malformed requests or responses that are
                //# detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
                let error_code = Code::H3_MESSAGE_ERROR;
                request_stream.stop_stream(error_code);
                request_stream.stop_sending(error_code);

                return Err(StreamError::StreamError {
                    code: error_code,
                    reason: format!("Malformed request with error: {}", err),
                });
            }
        };

        //  request_stream.stop_stream(Code::H3_MESSAGE_ERROR).await;

        let mut req = http::Request::new(());
        *req.method_mut() = method;
        *req.uri_mut() = uri;
        *req.headers_mut() = headers;
        // NOTE: insert `Protocol` and not `Option<Protocol>`
        if let Some(protocol) = protocol {
            req.extensions_mut().insert(protocol);
        }
        *req.version_mut() = http::Version::HTTP_3;
        #[cfg(feature = "tracing")]
        tracing::trace!("replying with: {:?}", req);

        Ok(req)
    }
}
