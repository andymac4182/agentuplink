# Independent authorization deadlines for handed-off work

Status: M4-76 source implementation and independent review complete; compilation,
formatting, regression execution and full acceptance remain pending. This is a
source-derived defect and correction, not an executed timing reproduction.

An unanswered refresh previously replaced a stream's last accepted confirmation
deadline. The HTTP read boundary checked expiry only while `confirmed` was true,
so work already handed to its exchange could outlive that earlier confirmation.
The filesystem provider did check freshness before host dispatch, but its shared
snapshot depended on the actor updating a freshness bit. A queued request could
therefore outlive the confirmation while the actor had not run another tick.
Existing new-DATA buffering, queue bounds and periodic expiry remain protections
within their own scopes.

## Correction

The M2 stream retains the last confirmed deadline separately from the current
challenge and operation deadline. Each bound keeps both clock anchors; combining
them through a minimum must not discard a wall-clock reversal anchor. Immediate
and deferred refresh admission preserve the accepted bound. Only a matching,
timely confirmation with a still-live shortened deadline renews authorization.
An already lapsed stream cannot be revived by a late confirmation.

The filesystem provider independently reads all three bounds immediately before
host work. The actor publishes them through a versioned atomic snapshot, with
sequentially consistent fields, checked nonwrapping versions, writer exclusion
and at most three read attempts. No unsafe code, new dependency or actor-blocking
lock is introduced. Snapshot contention can conservatively close a live session
with retryable 1011; this availability tradeoff is explicit and unmeasured.

The observed cause is carried into provider closure. Local elapsed authorization
remains 4006/1011; explicit invalidation remains 4001/1008. An unavailable snapshot
has a distinct internal cause and is not reported as a measured elapsed deadline
or revocation. Published terminal causes remain terminal. A clock-only snapshot
observation does not itself publish a terminal state, but a provider that refuses
dispatch closes permanently and cannot resume work after clock restoration or
snapshot renewal. Existing writer-deadline and transport-failure cleanup remain.

Cadence, quotas, replay, rotation, supported platforms and license policy are
unchanged. M4-47's recorded account-security rejection remains separate and is
not retried or bypassed by this change.

## Review and required execution

The isolated proposal starts from `753aeb5ca006889ce23b59be157342d4e72b6083`.
Its first review finds missing independent challenge publication at the provider
and a fallback that could lose an already published terminal cause. Two additional
test-source compile/lint mistakes are found by inspection; they are not executed
compiler failures. V2 corrects these findings. V3 clarifies clock-only observations,
uses a fixed-configuration clock witness, and adds a closed-provider continuation
after restored clock/renewal. Earlier drafts and review findings remain retained.

Final reviewed proposal tree: `670e5dc549531e5d7e0fd2cc85eff4b83cab1313`.
Patch SHA256: `3efbb61ec81b950b20d88aba40421dbf2e90428144a4dcb6a4a81fa38e8886f3`.
Independent final review SHA256:
`93415c6519a15763b249ddfc766ccfb505904c3bbc5ab12ac568aaa1df54a59b`.
All ten reviewed files integrate byte-for-byte on #288's source; their original
inputs are unchanged between the worker baseline and that candidate.

Twenty new tests cover HTTP reads, independent clock bounds, immediate/deferred
admission, late and timely renewal, shortened deadlines with no pending bytes,
provider-first refusal, terminal causes, snapshot contention/exhaustion, stream
isolation and writer-failure cleanup. They are **written but unrun**. The existing
filesystem guard-deletion matcher is adapted to the new equivalent close
expression with its original mutation and exact-match failure requirement intact;
the actual deletion witness still needs execution.

Required evidence includes fresh pinned formatting, strict all-target workspace
Clippy, locked workspace tests, meaningful behavioral RED controls, full affected
M1/M2/M3/M4/M7 acceptance and supported archive/platform checks at the final
candidate. Prior #287/#288 Rust passes do not verify these changed files. No local
native, formatter, compiler, Docker, Redis or cache execution has occurred.
