// Content and static markup for the interactive explainer on /docs/architecture.
// Build-time only: build-docs.cjs requires this file and writes its output into
// docs/architecture.html. The browser engine (architecture.js) holds no content;
// it reads the generated lists and data attributes, so every correction is made
// here, in the plain objects below.
//
// Sources: docs/cluster.md, docs/protocol.md, docs/architecture.md,
// docs/runtime.md, docs/http-forwarding.md.
//
// Placeholders: `$in` is the relay a consumer request enters, `$own` the relay
// that owns the device, `$new` the relay that takes over after a failure. In
// text, {in} {own} {new} become "Relay A" and so on. In `flow`, a trailing `<`
// plays the link backwards and `peer:x:y` is the peer link from x to y (dropped
// when x and y are the same relay).

const parts = {
  consumer: {
    name: 'Agent or application (consumer)',
    is: 'The agent or application that wants to use something on an enrolled computer. It can run anywhere, including the cloud.',
    holds: 'Its own access token from an external identity provider. It never holds a device certificate or a private relay address.',
    trusted: 'Only what tenant-scoped grants allow: a named device, a named service and the permitted operations.',
    lost: 'Its streams end. Work already running on the computer follows that capability\'s cancellation rules. Nothing is queued for later.',
  },
  lb: {
    name: 'Public load balancer',
    is: 'The public entry to the relays. It may hand any connection to any relay; no sticky routing is needed.',
    holds: 'No Agent Uplink state.',
    trusted: 'Reachability only. For device sockets it must pass TCP straight through, so mutual TLS ends inside the relay. Certificate headers forwarded from the internet are never trusted.',
    lost: 'No new connections reach the relays until it returns. Sockets passing through it drop and the client reconnects with backoff.',
  },
  relay: {
    name: 'Relay',
    is: 'A relay server. It serves public HTTPS for consumers, a mutual-TLS WebSocket listener for devices and a private HTTP/3 listener for other relays. The relay that owns a device is the only one that pairs its sockets, admits streams and coordinates rotation.',
    holds: 'Live sockets, per-stream sequence state and bounded buffers, all in memory, plus its own private keys. It has no catalog of its own.',
    trusted: 'Service traffic. A relay terminates TLS on both legs and can read what passes through it. This is not end-to-end encryption.',
    lost: 'Its device sessions and streams end. Devices it owned reconnect and get a new owner; in-memory state is not moved to another relay. The cluster design has been exercised with three relays in local harness runs, and complete cluster acceptance is still open.',
  },
  redis: {
    name: 'Redis (the single authoritative store)',
    is: 'The only shared storage and coordination authority.',
    holds: 'The durable catalog (tenants, memberships, identities, grants, device certificate registrations, revocation versions), the signed relay membership records, and short-lived presence, owner leases and one-use tickets. Never private keys, file contents, screenshots, MCP or ACP bodies, or replay buffers.',
    trusted: 'To be the one authority for authorization and ownership. It is not a root of trust: a key that merely appears in Redis proves nothing without a valid signature from the membership authority.',
    lost: 'Relays fail closed: readiness goes false, new work is refused and sessions close as their leases run out. The supported profile is one primary with no automatic promotion or failover. In a cluster, a Redis restart, restore or unclear primary needs an operator-approved recovery.',
  },
  authority: {
    name: 'Membership authority',
    is: 'An operator-run service, separate from the relays, that decides which relay public keys belong to this deployment. It signs one membership record per relay and answers signed checkpoint requests.',
    holds: 'The membership signing key, which stays outside Redis and outside ordinary relay configuration.',
    trusted: 'Cluster membership only. It cannot enrol a device or grant a consumer anything.',
    lost: 'Relays become unready and refuse new work as their signed records lapse (60-second lifetime, refreshed every 20 seconds). A relay that starts while the authority is unreachable stays unready. An outage shared by every relay does not, by itself, make them drop the devices they hold.',
  },
  device: {
    name: 'Client daemon',
    is: 'The Agent Uplink client running on the user\'s computer. It dials out to a relay. Nothing listens for inbound connections on the computer.',
    holds: 'The device private key and certificate, in protected local storage, and the local export configuration that names what may be reached.',
    trusted: 'The final decision. It checks every operation against the grant bound to the stream and against its own local configuration, so effective access is the intersection of the two.',
    lost: 'The device shows as offline and requests for it return a device-offline error; nothing is queued. It reconnects by itself with jittered exponential backoff (1 second rising to 60 by default) and starts a fresh session.',
  },
  caps: {
    name: 'Local capabilities',
    is: 'What the computer\'s owner chose to export: MCP servers, an ACP agent, confined filesystem mounts and fixed HTTP forwards. A computer-use adapter exists but is not enabled in shipped builds.',
    holds: 'Whatever the local service itself holds. A consumer cannot name an upstream URL, a command or a credential; targets are fixed in local configuration.',
    trusted: 'Only requests the daemon has already authorized.',
    lost: 'The operation fails or its outcome is reported as unknown. It is not retried automatically.',
  },
  'l-public': {
    name: 'Public HTTPS',
    is: 'Consumer requests to a relay\'s public listener, authenticated with the consumer\'s access token. Filesystem clients upgrade the same kind of request to a WebSocket.',
    holds: 'Requests and responses in transit. Tokens travel in headers, never in URLs.',
    trusted: 'TLS protects this leg. The relay at the end of it can read the content.',
    lost: 'The request ends. If it had already been dispatched, its outcome may be unknown.',
  },
  'l-peer': {
    name: 'Private peer link (HTTP/3)',
    is: 'HTTP/3 over QUIC between two relays, opened on demand, with mutual TLS using relay identities that are separate from device credentials. It carries an exchange from the relay that received it to the relay that owns the device.',
    holds: 'Bounded, framed bytes for the forwarded exchange. The hop budget is exactly one: a relay never forwards onward.',
    trusted: 'Only peers whose key is approved by a current signed membership record. There is no fallback to HTTP/2 or plain TCP.',
    lost: 'Before dispatch the consumer gets a retryable error marked as not dispatched. After dispatch the result is reported as interrupted or unknown.',
  },
  'l-store': {
    name: 'Relay to Redis',
    is: 'Each relay\'s authenticated TLS connection to Redis.',
    holds: 'Catalog reads, atomic authorization and lease scripts, and membership record reads.',
    trusted: 'Atomic scripts. Ownership and authorization are never a check followed by a separate write.',
    lost: 'That relay stops admitting work at once (authority calls time out after 2 seconds) and closes sessions as its leases run out.',
  },
  'l-trust': {
    name: 'Signed membership records',
    is: 'The authority publishes signed records into Redis. Relays read them there and verify each signature against a key the operator installed.',
    holds: 'Public keys, private-network endpoints and validity windows. No private keys and no root of trust.',
    trusted: 'The signature, not the storage. A successful Redis read never extends a record past its signed expiry.',
    lost: 'Records lapse after their signed lifetime and relays stop trusting each other as peers.',
  },
  'l-control': {
    name: 'Control socket',
    is: 'The first outbound WebSocket, with mutual TLS. It carries the handshake, stream admission, cancellation, heartbeats, authorization and ownership confirmations, and rotation coordination.',
    holds: 'Small bounded control messages (32 KiB ceiling). No payloads.',
    trusted: 'The device identity in its certificate, verified before the WebSocket upgrade.',
    lost: 'The relay stops admitting operations for that device. A reconnect starts a fresh session.',
  },
  'l-data': {
    name: 'Data socket',
    is: 'The second outbound WebSocket, also mutual TLS, admitted only with a single-use ticket issued over the control socket. It multiplexes the payloads of every stream.',
    holds: 'Binary frames with a sequence number per stream and direction. In a cluster it may be accepted by a different relay, which forwards it to the owner over the peer link.',
    trusted: 'The device certificate and the ticket together. Neither alone attaches a data socket.',
    lost: 'While the control socket is healthy the owner authorizes a replacement and resumes from retained sequence state, within a bounded number of attempts.',
  },
  'l-candidate': {
    name: 'Replacement data socket',
    is: 'The temporary third socket during a rotation. The overlap is bounded: 30 seconds in total, and the candidate must attach within 10.',
    holds: 'Nothing sequenced until the rotation commits.',
    trusted: 'The same as the data socket: the device certificate plus a fresh single-use ticket.',
    lost: 'If it fails before the commit, the rotation is aborted and the old socket carries on.',
  },
  'l-local': {
    name: 'Local hand-off',
    is: 'The daemon calling the configured local service on the same computer: a supervised process over stdio, a fixed local HTTP endpoint, or its built-in filesystem server.',
    holds: 'The request and response for that operation.',
    trusted: 'Fixed targets from local configuration. The consumer\'s credential is never forwarded to the device.',
    lost: 'The operation fails or is reported as outcome unknown.',
  },
};

const scenes = [
  {
    id: 'cluster',
    tab: 'Relay cluster',
    title: 'How the relay cluster passes connections between servers',
    intro: 'Several relays share one Redis. A device is owned by exactly one relay at a time, a request may arrive at any of them, and the relays forward to the owner over a private link.',
    ingress: true,
    main: [
      { title: 'Several relays, one entry', nodes: 'lb relay-a relay-b relay-c', links: 'lb-a lb-b lb-c',
        text: 'The diagram shows three relays, the size the repository\'s cluster harness uses; signed membership allows up to 32. Any relay can accept a consumer request or a device socket.' },
      { title: 'One authoritative store', nodes: 'redis', links: 'store-a store-b store-c',
        text: 'A single Redis is the only shared store. It holds the catalog of grants, the device ownership leases and the signed membership records. It holds no payloads, sockets, private keys or replay buffers.' },
      { title: 'Who is a relay', nodes: 'authority redis', flow: 'trust',
        text: 'A separate membership authority signs the approved set of relay public keys. Redis only distributes those signed records; it is not a root of trust and never holds private keys.' },
      { title: 'Private peer links', nodes: 'relay-a relay-b relay-c', links: 'peer-a-b peer-b-c peer-a-c',
        text: 'Relays talk to each other only over private HTTP/3 (QUIC) with mutual TLS, using relay identities that are distinct from device credentials. A device certificate cannot act as a peer.' },
      { title: 'One relay owns the device', nodes: 'device relay-$own redis', flow: 'ctl-$own store-$own',
        text: 'The device\'s control socket reaches {own}, which claims the owner lease for that device in Redis with one atomic script. The lease lasts 30 seconds by default and is renewed every 10.' },
      { title: 'A request arrives anywhere', nodes: 'consumer lb relay-$in redis', flow: 'pub lb-$in store-$in',
        text: 'A consumer request lands on {in}; the load balancer needs no sticky routing. {in} authenticates and authorizes the request, then looks up the device\'s owner in Redis.' },
      { title: 'Forward once to the owner', when: 'forward', nodes: 'relay-$in relay-$own', flow: 'peer:$in:$own',
        text: '{in} forwards the exchange straight to {own} over the private peer link. The hop budget is exactly one: a relay that is not the owner answers that the owner changed instead of forwarding onward.' },
      { title: 'No hop needed', when: 'local', nodes: 'relay-$in',
        text: 'Here the request entered at the relay that already owns the device, so nothing is forwarded.' },
      { title: 'The owner delivers', nodes: 'relay-$own device', flow: 'data-$own<',
        text: '{own} repeats the authorization check, confirms it still holds the lease and sends the exchange down the device\'s data socket.' },
      { title: 'The response returns', nodes: 'device relay-$own relay-$in consumer', flow: 'data-$own peer:$own:$in lb-$in< pub<',
        text: 'The response travels back the same way. Relay-to-relay ordering does not create a global order across streams, and it never authorizes a retry.' },
    ],
    altHeading: 'If the owning relay stops',
    altLabel: 'Stop the owning relay',
    altBack: 'Restore the cluster',
    alt: [
      { title: 'The owner stops', nodes: 'relay-$own device', owner: 'none', down: '$own', sockets: '',
        text: '{own} stops. Its device sessions end, and so do the streams that were riding on them. Nothing held in its memory moves to another relay.' },
      { title: 'In-flight work is not replayed', nodes: 'consumer', owner: 'none', down: '$own', sockets: '',
        text: 'A request that had already been dispatched ends with an explicit interrupted or unknown outcome. The relay never replays it; the consumer decides whether to try again.' },
      { title: 'The lease is released or expires', nodes: 'redis', owner: 'none', down: '$own', sockets: '',
        text: 'On a clean stop the relay releases its lease at once. After a crash the lease stays in Redis until it expires, 30 seconds by default, and reconnects are refused as owner-busy until then.' },
      { title: 'The device reconnects', nodes: 'device lb relay-$new', flow: 'ctl-$new', owner: 'none', down: '$own', at: '$new', sockets: 'ctl',
        text: 'The client retries with backoff. The load balancer hands its new control socket to another relay, here {new}.' },
      { title: 'A new owner under a newer fence', nodes: 'relay-$new redis device', flow: 'store-$new data-$new', owner: '$new', down: '$own', sockets: 'ctl data',
        text: '{new} claims the lease. Redis increments the device\'s owner epoch, so the new owner token outranks the old one, and the device starts a fresh session.' },
      { title: 'A stale owner is refused', nodes: 'relay-$own redis', flow: 'store-$own', owner: '$new', stale: '$own', sockets: 'ctl data',
        text: 'If {own} comes back still believing it is the owner, its renewal and release compare the full owner token and fail. The device has already rejected the old owner before acknowledging the new one.' },
      { title: 'Requests find the new owner', nodes: 'consumer lb relay-$in relay-$new device', flow: 'pub lb-$in peer:$in:$new data-$new<', owner: '$new', sockets: 'ctl data',
        text: 'The next request performs a fresh owner lookup and is routed to {new}. Sessions that cannot survive an owner change, such as open filesystem handles, start again.' },
    ],
  },
  {
    id: 'daemon',
    tab: 'Daemon connection',
    title: 'How the daemon on the user\'s computer connects',
    intro: 'The client only ever dials out. It holds two WebSockets in steady state, both authenticated with the device\'s own certificate, and briefly a third while the data socket is rotated.',
    main: [
      { title: 'Outbound only', nodes: 'device lb relay-$own', flow: 'ctl-$own', sockets: 'ctl',
        text: 'The client dials the relay\'s device listener. The computer opens no inbound port, and the load balancer passes TCP straight through so the TLS handshake ends inside the relay.' },
      { title: 'Control socket with mutual TLS', nodes: 'device relay-$own', flow: 'ctl-$own', sockets: 'ctl',
        text: 'The client verifies the relay\'s certificate and presents its per-device certificate. The relay checks the chain, identity, validity and revocation before it accepts the WebSocket.' },
      { title: 'Hello, welcome and ownership', nodes: 'device relay-$own redis', flow: 'ctl-$own store-$own ctl-$own<', sockets: 'ctl',
        text: 'The client says hello and the two agree a protocol version. The relay takes ownership of the device and replies with the session, its limits, the heartbeat and rotation policy, and a short-lived single-use ticket.' },
      { title: 'Data socket with certificate and ticket', nodes: 'device relay-$own', flow: 'data-$own',
        text: 'The client opens a second outbound WebSocket, again with mutual TLS, and presents the ticket. The owner consumes the ticket once; the certificate and the ticket are both required.' },
      { title: 'Two sockets in steady state', nodes: 'device relay-$own', links: 'ctl-$own data-$own',
        text: 'The relay reports that data is ready and only then admits streams. The control socket carries coordination; the data socket carries every stream\'s payload.' },
      { title: 'Heartbeats', nodes: 'device relay-$own redis', flow: 'ctl-$own ctl-$own< store-$own',
        text: 'The protocol document proposes a control heartbeat every 20 seconds, with the peer counted lost after 60 without a valid reply. A heartbeat does not renew ownership; the lease is renewed separately.' },
      { title: 'Reconnect with backoff', nodes: 'device', flow: 'ctl-$own', sockets: 'ctl',
        text: 'If the session ends, the client retries with jittered exponential backoff, from 1 second up to 60 by default. A refused certificate or bad configuration is final and is not retried.' },
    ],
    altHeading: 'Rotating the data socket',
    altLabel: 'Rotate now',
    altBack: 'Back to steady state',
    alt: [
      { title: 'Prepare a third socket', nodes: 'device relay-$own', flow: 'ctl-$own< cand-$own', sockets: 'ctl data cand',
        text: 'Every 300 seconds by default the owner asks for a rotation and issues a fresh ticket. The client opens a replacement data socket, so for a bounded time there are three sockets.' },
      { title: 'Pause new streams', nodes: 'relay-$own', links: 'ctl-$own', sockets: 'ctl data cand',
        text: 'The owner pauses new stream opens and fixes the list of streams this rotation covers. A request arriving now is held for at most 1.5 seconds, then refused as not dispatched and retryable.' },
      { title: 'Writes freeze at a fence', nodes: 'device relay-$own', flow: 'ctl-$own ctl-$own<', sockets: 'ctl data cand',
        text: 'Each side stops writing new frames to the old socket and flushes what it had queued. It then reports, for every stream and direction, the last sequence number it sent. That fence cannot change.' },
      { title: 'Drain to the fence', nodes: 'device relay-$own', flow: 'data-$own data-$own<', sockets: 'ctl data cand',
        text: 'Each receiver keeps reading the old socket until it has every frame up to the fence, with no gaps, and then reports it has drained. Nothing sequenced travels on the replacement yet.' },
      { title: 'Commit the replacement', nodes: 'device relay-$own', flow: 'ctl-$own< cand-$own cand-$own<', sockets: 'ctl data cand',
        text: 'With both drain reports in hand the owner commits. Writers resume on the replacement socket and sequence numbers carry on above the fences, so nothing is replayed.' },
      { title: 'Retire the old socket', nodes: 'device relay-$own', links: 'ctl-$own cand-$own', sockets: 'ctl cand', promoted: true,
        text: 'Both sides close the old data socket and the device is back to two sockets. Open streams continue without reopening. Drained means the bytes are accounted for, not that an operation finished.' },
    ],
  },
  {
    id: 'agent',
    tab: 'Agent request',
    title: 'How an agent talks through the relays to the daemon',
    intro: 'A request names one device and one service. It is authorized at the relay, routed to the owner, and checked again on the computer before anything local runs.',
    ingress: true,
    note: 'The relay terminates TLS and can see service traffic. This is not end-to-end encryption.',
    main: [
      { title: 'The agent presents a token', nodes: 'consumer lb relay-$in', flow: 'pub lb-$in',
        text: 'The agent or application, the consumer, sends an HTTPS request that names a device and a service to a relay\'s public listener, with its access token in a header.' },
      { title: 'The relay authorizes it', nodes: 'relay-$in redis', flow: 'store-$in store-$in<',
        text: '{in} takes the tenant from the authenticated token and checks the grant for that exact device and service in Redis, atomically, against one consistent catalog revision.' },
      { title: 'Route to the owner', when: 'forward', nodes: 'relay-$in relay-$own', flow: 'peer:$in:$own',
        text: '{in} is not the device\'s owner, so it forwards the exchange once to {own} over the private peer link. {own} validates the token and the grant again itself.' },
      { title: 'Already at the owner', when: 'local', nodes: 'relay-$in',
        text: '{in} owns this device, so the exchange stays on one relay.' },
      { title: 'Down the data socket', nodes: 'relay-$own device', flow: 'ctl-$own< data-$own<',
        text: 'The owner opens a logical stream on the control socket and sends the request frames down the device\'s data socket, each with its stream\'s sequence number.' },
      { title: 'The daemon checks for itself', nodes: 'device relay-$own', flow: 'ctl-$own ctl-$own<',
        text: 'Before running anything the daemon confirms the authorization with the owner, valid for at most 5 seconds, and checks its own local export configuration. Access is the intersection of the grant and the local exports.' },
      { title: 'Hand-off to the local capability', nodes: 'device caps', flow: 'local',
        text: 'The daemon hands the request to the configured capability: an MCP server, an ACP agent, a filesystem export or a fixed HTTP forward. Computer use exists but is not enabled in shipped builds.' },
      { title: 'The response returns', nodes: 'caps device relay-$own relay-$in consumer', flow: 'local< data-$own peer:$own:$in lb-$in< pub<',
        text: 'The response returns the same way: data socket, owner relay, peer link if there was one, and back to the consumer.' },
      { title: 'An acknowledgement is not completion', nodes: 'device caps',
        text: 'A transport acknowledgement shows that frames arrived, not that the action completed. If the connection is lost mid-operation the outcome is reported as unknown and is not replayed.' },
      { title: 'The trust boundary', nodes: 'relay-$in relay-$own',
        text: 'TLS protects each leg, but the relay terminates it and can see service traffic. This is not end-to-end encryption, and the local allowlist still applies with a trusted relay.' },
    ],
  },
];

// Geometry. Two layouts of the same diagram: wide for roomy containers, narrow
// (taller, larger text) for phones. architecture.css picks one by container width.
const relayIds = ['a', 'b', 'c'];
const layouts = {
  wide: {
    viewBox: '20 0 840 566',
    nodes: {
      consumer: [40, 10, 240, 56, 'Agent or application', 'the consumer, running anywhere'],
      authority: [600, 10, 240, 56, 'Membership authority', 'signs approved relay keys'],
      lb: [40, 104, 400, 48, 'Public load balancer', 'any relay, no sticky routing'],
      redis: [600, 104, 240, 48, 'Redis', 'catalog, leases, signed records'],
      'relay-a': [40, 230, 220, 74], 'relay-b': [320, 230, 220, 74], 'relay-c': [600, 230, 220, 74],
      device: [280, 414, 300, 60, 'Client daemon', 'on the user\'s computer'],
      caps: [280, 504, 300, 52, 'Local capabilities', 'MCP · ACP · files · HTTP forward'],
    },
    lbX: [110, 240, 370], redisX: [650, 720, 790], topOffset: 40,
    socketX: [380, 430, 480], socketOffset: [-50, 0, 50],
    arc: 'M 240 304 Q 430 366 620 304',
    boundary: { y: 376, x1: 40, x2: 840, label: 'The user\'s computer · outbound only', lx: 40, ly: 396 },
    packet: 7,
  },
  narrow: {
    viewBox: '0 0 300 494',
    nodes: {
      consumer: [4, 6, 138, 50, 'Agent or app', 'the consumer'],
      authority: [158, 6, 138, 50, 'Authority', 'signs relay keys'],
      lb: [4, 86, 138, 46, 'Load balancer', 'public entry'],
      redis: [158, 86, 138, 46, 'Redis', 'catalog + leases'],
      'relay-a': [0, 196, 88, 74], 'relay-b': [106, 196, 88, 74], 'relay-c': [212, 196, 88, 74],
      device: [30, 348, 240, 56, 'Client daemon', 'outbound only, no inbound port'],
      caps: [30, 434, 240, 52, 'Local capabilities', 'MCP · ACP · files · HTTP'],
    },
    lbX: [30, 73, 116], redisX: [184, 227, 270], topOffset: 16,
    socketX: [110, 150, 190], socketOffset: [-24, -4, 16],
    arc: 'M 76 270 Q 150 306 224 270',
    boundary: { y: 320, x1: 0, x2: 300 },
    packet: 6,
  },
};

const esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const relayName = id => `Relay ${id.toUpperCase()}`;
const defaults = { in: 'a', own: 'b', new: 'a' };

function links(layout) {
  const n = layout.nodes;
  const cx = id => n[id][0] + n[id][2] / 2;
  const bottom = id => n[id][1] + n[id][3];
  const line = (x1, y1, x2, y2) => `M ${x1} ${y1} L ${x2} ${y2}`;
  const out = [
    ['pub', 'public', 'l-public', 'Public HTTPS from the consumer to the load balancer', line(cx('consumer'), bottom('consumer'), cx('consumer'), n.lb[1])],
    ['trust', 'trust', 'l-trust', 'Signed membership records from the authority into Redis', line(cx('authority'), bottom('authority'), cx('authority'), n.redis[1])],
  ];
  relayIds.forEach((id, i) => {
    const relay = `relay-${id}`;
    out.push([`lb-${id}`, 'public', 'l-public', `Public traffic from the load balancer to ${relayName(id)}`, line(layout.lbX[i], bottom('lb'), cx(relay) - layout.topOffset, n[relay][1])]);
    out.push([`store-${id}`, 'store', 'l-store', `${relayName(id)} to Redis`, line(cx(relay) + layout.topOffset, n[relay][1], layout.redisX[i], bottom('redis'))]);
  });
  const mid = n['relay-a'][1] + n['relay-a'][3] / 2;
  out.push(['peer-a-b', 'peer', 'l-peer', 'Private peer link between Relay A and Relay B', line(n['relay-a'][0] + n['relay-a'][2], mid, n['relay-b'][0], mid)]);
  out.push(['peer-b-c', 'peer', 'l-peer', 'Private peer link between Relay B and Relay C', line(n['relay-b'][0] + n['relay-b'][2], mid, n['relay-c'][0], mid)]);
  out.push(['peer-a-c', 'peer', 'l-peer', 'Private peer link between Relay A and Relay C', layout.arc]);
  for (const id of relayIds) {
    const relay = `relay-${id}`;
    [['ctl', 'l-control', 'Control socket'], ['data', 'l-data', 'Data socket'], ['cand', 'l-candidate', 'Replacement data socket']].forEach(([kind, part, name], i) => {
      const shown = id === defaults.own && kind !== 'cand';
      out.push([`${kind}-${id}`, kind, part, `${name} from the client daemon to ${relayName(id)}`, line(layout.socketX[i], n.device[1], cx(relay) + layout.socketOffset[i], bottom(relay)), !shown]);
    });
  }
  out.push(['local', 'local', 'l-local', 'Local hand-off from the daemon to a capability', line(cx('device'), bottom('device'), cx('device'), n.caps[1])]);
  return out;
}

function svg(name) {
  const layout = layouts[name];
  const node = ([id, [x, y, w, h, label, sub]]) => {
    const relay = id.startsWith('relay-') ? id.slice(6) : null;
    const part = relay ? 'relay' : id;
    const cx = x + w / 2;
    let text;
    let state = '';
    if (relay) {
      const roles = [relay === defaults.in ? 'entry' : '', relay === defaults.own ? 'owner' : ''].filter(Boolean);
      if (relay === defaults.own) state = ' is-owner';
      text = `<text class="ax-label" x="${cx}" y="${y + 25}">${relayName(relay)}</text><text class="ax-role" data-role-line="1" x="${cx}" y="${y + 45}">${roles[0] || ''}</text><text class="ax-role" data-role-line="2" x="${cx}" y="${y + 63}">${roles[1] || ''}</text>`;
    } else {
      text = `<text class="ax-label" x="${cx}" y="${y + h / 2 - 3}">${esc(label)}</text><text class="ax-sub" x="${cx}" y="${y + h / 2 + 15}">${esc(sub)}</text>`;
    }
    return `<g class="ax-node ax-n-${part}${state}" data-node="${id}" data-part="${part}" data-name="${esc(relay ? relayName(relay) : parts[part].name)}"><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="6"/>${text}</g>`;
  };
  const link = ([id, kind, part, title, d, off]) => `<g class="ax-link ax-k-${kind}${off ? ' is-off' : ''}" data-link="${id}" data-part="${part}" data-name="${esc(title)}"><path class="ax-link-hit" d="${d}"/><path class="ax-link-line" d="${d}"/></g>`;
  const b = layout.boundary;
  return `<svg class="ax-svg ax-${name}" data-packet="${layout.packet}" viewBox="${layout.viewBox}" role="img" aria-labelledby="ax-svg-title-${name} ax-svg-desc-${name}" xmlns="http://www.w3.org/2000/svg"><title id="ax-svg-title-${name}">Agent Uplink architecture diagram</title><desc id="ax-svg-desc-${name}">An agent or application reaches a public load balancer in front of three relays. The relays share one Redis, whose membership records are signed by a separate authority, and reach each other over private peer links. A client daemon on the user's computer holds an outbound control socket and data socket to the relay that owns it, and hands requests to local capabilities. The numbered steps below the diagram describe each flow in words.</desc><line class="ax-boundary" x1="${b.x1}" y1="${b.y}" x2="${b.x2}" y2="${b.y}"/>${b.label ? `<text class="ax-zone" x="${b.lx}" y="${b.ly}">${esc(b.label)}</text>` : ''}<g class="ax-links">${links(layout).map(link).join('')}</g><g class="ax-nodes">${Object.entries(layout.nodes).map(node).join('')}</g><g class="ax-packets" aria-hidden="true"></g></svg>`;
}

const fill = text => esc(text).replace(/\{(in|own|new)\}/g, (_, key) => `<span data-var="${key}">${relayName(defaults[key])}</span>`);

function steps(list, seq) {
  const attrs = step => ['nodes', 'links', 'flow', 'when', 'owner', 'down', 'stale', 'at', 'sockets', 'promoted']
    .filter(key => step[key] !== undefined)
    .map(key => ` data-${key}="${esc(step[key] === true ? '1' : step[key])}"`).join('');
  return `<ol class="ax-steps" data-seq="${seq}">${list.map(step => `<li${attrs(step)}><strong class="ax-step-title">${esc(step.title)}.</strong> <span class="ax-step-text">${fill(step.text)}</span>${step.when ? ` <em class="ax-step-when">${step.when === 'forward' ? 'Applies when the request enters at a relay that does not own the device.' : 'Applies when the request enters at the owning relay.'}</em>` : ''}</li>`).join('')}</ol>`;
}

function scene(item, index) {
  const alt = item.alt
    ? `<h4 class="ax-alt-heading" data-alt-label="${esc(item.altLabel)}" data-alt-back="${esc(item.altBack)}">${esc(item.altHeading)}</h4>${steps(item.alt, 'alt')}`
    : '';
  return `<section class="ax-scene" id="ax-scene-${item.id}" data-scene="${item.id}" data-tab="${esc(item.tab)}"${item.ingress ? ' data-ingress="1"' : ''}><h3>${index + 1}. ${esc(item.title)}</h3><p class="ax-scene-intro">${esc(item.intro)}</p>${item.note ? `<aside class="note">${esc(item.note)}</aside>` : ''}${steps(item.main, 'main')}${alt}</section>`;
}

const legend = [['public', 'Public HTTPS'], ['peer', 'Private peer link (HTTP/3)'], ['store', 'Redis and signed records'], ['ctl', 'Control socket'], ['data', 'Data socket'], ['cand', 'Replacement socket'], ['local', 'Local hand-off']];

function partsList() {
  return Object.entries(parts).map(([id, part]) => `<article class="ax-part" data-part-info="${id}"><h4>${esc(part.name)}</h4><dl><dt>What it is</dt><dd>${esc(part.is)}</dd><dt>What it holds</dt><dd>${esc(part.holds)}</dd><dt>What it is trusted with</dt><dd>${esc(part.trusted)}</dd><dt>If it is lost</dt><dd>${esc(part.lost)}</dd></dl></article>`).join('');
}

function render() {
  return `<section class="ax" data-ax aria-labelledby="ax-title"><h2 id="ax-title">How it fits together</h2><p>Three flows, one diagram: how the relays share a device, how the client daemon connects, and how an agent's request reaches a local capability. This describes the documented design. The cluster profile has local harness evidence only and its acceptance is still open.</p><div class="ax-stage"><figure class="ax-figure">${svg('wide')}${svg('narrow')}<figcaption class="ax-legend">${legend.map(([kind, label]) => `<span class="ax-key"><svg class="ax-key-line ax-k-${kind}" viewBox="0 0 34 8" aria-hidden="true"><path class="ax-link-line" d="M 1 4 L 33 4"/></svg>${esc(label)}</span>`).join('')}</figcaption></figure></div><div class="ax-scenes">${scenes.map(scene).join('')}</div><details class="ax-parts"><summary>Every part of the diagram, in words</summary>${partsList()}</details></section>`;
}

module.exports = { render, scenes, parts };
