# EternalCore v4 Authorization and Policy Specification

> Status: implementation baseline
>
> This document defines the authoritative authorization semantics for EternalCore v4. It is subordinate to `ARCHITECTURE.md` for system architecture, to `FORMAT.md` for bytes and identifiers, to `TRANSACTIONS.md` for publication ordering and crash semantics, and to `CRYPTO.md` for cryptographic validation. Where an older draft conflicts with this document, this document wins for authorization behavior.

## 1. Purpose and scope

EternalCore separates cryptographic identity from authority.

A valid signature proves that a known private key signed a specific immutable payload. It does not prove that the signer was permitted to alter repository state, advance policy, change encryption keys, or update a ref.

This document defines:

- the repository trust anchor;
- the immutable public-key registry;
- policy-chain validation;
- administrator, writer, tag-creator, and per-ref authority;
- authorization of `ObjectVersion`, `RepoCommit`, `KeyringRecord`, and `RefUpdate` records;
- branch-local policy evolution;
- revocation and historical authorization;
- policy behavior during merge, sync, partial clone, rollback, and recovery;
- deterministic authorization algorithms and error classifications;
- implementation APIs and mandatory tests.

This document does not define:

- record encoding or field numbers;
- signature equations or key-wrapping algorithms;
- transaction durability;
- transport framing;
- operating-system user permissions;
- semantic review of user content;
- Byzantine consensus among mutually distrustful administrators.

## 2. Normative language

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY are normative.

A conforming implementation MUST produce the same authorization result for the same validated repository graph, ref name, and candidate transition.

Authorization MUST NOT depend on:

- local wall-clock time;
- filesystem modification time;
- record arrival order;
- cache contents;
- remote reputation;
- mutable `config.toml` values;
- a key label;
- the physical pack containing a record;
- whether a signature was generated locally.

## 3. Security model

### 3.1 Trust anchor

The sole repository trust bootstrap is the signed `RepositoryGenesis` record named by the repository bootstrap layout.

The genesis record binds:

- `repository_id`;
- `federation_id`;
- the creator Ed25519 public key and `creator_key_id`;
- `initial_policy_id`;
- `initial_keyring_id`.

The creator key is trusted only because its exact bytes are embedded in the validated genesis record. No local key file, network response, or `trusted_keys/` cache can replace or override this anchor.

### 3.2 Immutable evidence, mutable authority

The following are immutable evidence:

- public keys introduced by valid policy ancestry;
- signatures;
- policy records;
- keyring records;
- object versions;
- repository commits;
- ref updates.

The current authority of a branch is determined by the validated policy selected through that branch's ref and commit history. Authority is therefore historical and branch-relative, not a timeless property of a key.

### 3.3 Signature validity is not authorization

The implementation MUST distinguish:

```text
record integrity
signature validity
key identity
historical key registration
operation authorization
state-transition validity
ref publication
```

A record may be correctly encoded, correctly hashed, and correctly signed while still being unauthorized.

### 3.4 Threats addressed

The policy model is designed to reject:

- self-authorizing policy changes;
- use of a newly introduced key before the introducing policy becomes authoritative;
- reuse of a revoked key for future state transitions;
- per-ref permission bypass;
- tag mutation;
- ref ABA attacks;
- branch creation from an unanchored, attacker-created history;
- privilege obtained from timestamps;
- replacement of a historical public key under the same `KeyId`;
- silent policy adoption from a non-baseline merge parent;
- local-cache substitution for immutable policy evidence;
- remote publication of a graph whose commit or ref signer lacks authority.

### 3.5 Threats not addressed

The policy model does not prevent:

- an authorized writer from publishing harmful or incorrect content;
- an authorized administrator from granting excessive authority;
- collusion among all current administrators;
- use of a private key stolen before its revocation becomes authoritative;
- rollback of an entire local repository to an older, internally valid state when no external trusted tip exists;
- disclosure of metadata to a node that is already allowed to receive repository metadata;
- denial of service through refusal to sign, merge, or publish;
- loss of all administrator keys.

## 4. Identity and key registry

### 4.1 Key types

`PolicyRecord.introduced_keys` may register:

- algorithm 1: Ed25519 public keys;
- algorithm 2: X25519 public keys.

Only Ed25519 keys can hold authorization roles in format v1.

X25519 keys may be referenced by recipient or recovery key slots, but MUST NOT appear in:

- `administrators`;
- `writers`;
- `per_ref_permissions[*].writers`;
- `tag_creators`;
- `revoked_keys` as an authorization revocation mechanism for signing operations.

An X25519 key may still be operationally retired by omitting future recipient slots. Its historical public-key entry remains immutable evidence.

### 4.2 Effective public-key registry

For a validated policy `P`, its effective key registry is:

```text
Registry(P) = creator key from genesis
              union all introduced_keys from P's policy ancestry
```

The registry is append-only.

A later policy MUST NOT:

- remove an introduced key from historical interpretation;
- reintroduce an existing `KeyId` with different bytes;
- reintroduce an existing `KeyId` under another algorithm;
- introduce two entries with the same `KeyId`;
- introduce a key whose recomputed `KeyId` differs from the entry.

Reintroducing the exact same key entry is invalid rather than silently ignored. This keeps each key introduction unique and audit-visible.

### 4.3 Labels

A public-key label is descriptive metadata only. It grants no authority and may not be used in authorization decisions.

Applications MUST display `KeyId` whenever a decision is security-sensitive. A label collision or label change must not affect authorization.

### 4.4 Unknown keys

A signed record whose signer key cannot be resolved from the genesis key or valid policy ancestry fails with `UnknownSigningKey`.

A local public-key file that is not represented in immutable policy history does not make the key known for repository validation.

## 5. PolicyRecord state

### 5.1 Effective policy

A `PolicyRecordPayload` is a complete authorization snapshot, not a patch.

The following fields replace their predecessors completely:

- `administrators`;
- `writers`;
- `per_ref_permissions`;
- `tag_creators`.

The following state is cumulative:

- the public-key registry, through `introduced_keys` ancestry;
- `revoked_keys`.

A writer MUST construct a new policy by explicitly carrying forward every role and permission that should remain active.

### 5.2 Initial policy

The initial policy MUST satisfy all of the following:

- `previous_policy_id = null`;
- `policy_sequence = 1`;
- its `PolicyId` equals `RepositoryGenesis.initial_policy_id`;
- its `repository_id` equals the genesis repository ID;
- it is signed by the genesis creator key;
- `author_key_id` equals `creator_key_id`;
- the creator key is not reintroduced in `introduced_keys`;
- every other referenced key is introduced in the initial policy;
- at least one unrevoked administrator exists.

The initial policy is authorized by the genesis trust anchor, not by itself.

### 5.3 Subsequent policy transition

A candidate policy `New` extending `Old` is valid only when:

1. `New.previous_policy_id == PolicyId(Old)`;
2. `New.policy_sequence == Old.policy_sequence + 1`;
3. the sequence increment does not overflow `u64`;
4. `New.repository_id == Old.repository_id`;
5. `New.author_key_id` is an Ed25519 key in `Registry(Old)`;
6. `New.author_key_id` is in `Old.administrators`;
7. `New.author_key_id` is not in `Old.revoked_keys`;
8. the detached signature verifies under that exact public key;
9. every introduced key validates and is new to `Registry(Old)`;
10. every role and permission member resolves to an Ed25519 key in `Registry(New)`;
11. `New.revoked_keys` is a superset of `Old.revoked_keys`;
12. no key in `New.revoked_keys` appears in an active role or ref permission in `New`;
13. at least one unrevoked administrator remains in `New`;
14. all canonical ordering and uniqueness rules in `FORMAT.md` hold.

A policy transition is invalid if any condition fails. Implementations MUST NOT attempt to repair or normalize an invalid signed policy.

### 5.4 No un-revocation

Revocation is cumulative and irreversible within one `repository_id`.

A key in any ancestor's `revoked_keys` MUST appear in every descendant policy's `revoked_keys`.

The same key cannot be restored by:

- omitting it from a later `revoked_keys` list;
- reintroducing its public key;
- changing its label;
- assigning it to a role;
- claiming an earlier timestamp.

Restoring control to the same human or device requires introducing a new keypair with a new `KeyId`.

### 5.5 Administrator liveness

Format v1 requires every valid policy to contain at least one unrevoked administrator.

A policy that would leave zero administrators is invalid. EternalCore v4 does not encode a separate permanently sealed policy state.

This rule prevents accidental creation of an unverifiable or unmaintainable authority chain. A repository intended as a frozen archive should retain an offline administrator key and deny all ref writers instead of removing every administrator.

### 5.6 Read-only policy

A policy MAY contain:

- an empty `writers` set;
- empty per-ref writer sets;
- an empty `tag_creators` set.

Such a policy can make all data refs read-only while preserving policy-administration capability.

An empty writer set in a matching `RefPermissionEntry` is an explicit deny-all rule for that ref namespace.

## 6. Roles and capabilities

### 6.1 Role matrix

| Operation | Required authority |
|---|---|
| Create a detached `ObjectVersion` | known Ed25519 key; no state authority by itself |
| Create a regular or merge `RepoCommit` | active global writer under first-parent policy |
| Create a `PolicyRecord` | active administrator under previous policy |
| Publish a policy administrative commit | valid policy transition; commit signer is the same active administrator |
| Create a `KeyringRecord` | active administrator under current policy |
| Publish a keyring administrative commit | valid keyring transition; commit signer is the same active administrator |
| Update/delete/recreate a branch | signer allowed by resolved ref-write permission |
| Create a tag | signer allowed by resolved ref-write permission and in `tag_creators` |
| Modify/delete/recreate a tag | forbidden in format v1 |
| Update a pin or merge-request ref | signer allowed by resolved ref-write permission |
| Change local `HEAD` | local filesystem authority only; not a repository policy operation |
| Repack, seal, rebuild cache | local storage authority only; no logical policy change |
| Fetch immutable records | transport/session rules; no authority to publish refs |

### 6.2 Administrators

Administrators may:

- sign the next policy transition;
- sign the next keyring transition;
- sign the corresponding administrative commit;
- introduce new public keys through policy;
- assign and remove roles;
- revoke signing keys.

Administrators do not automatically receive:

- global writer authority;
- per-ref writer authority;
- tag-creation authority;
- content decryption capability;
- recipient-key capability;
- transport admission.

An administrator who must also update a ref must be independently authorized for that ref, or an authorized ref writer must publish the valid administrative commit.

This separation is deliberate.

### 6.3 Global writers

`PolicyRecord.writers` is the set of Ed25519 keys permitted to sign regular and merge `RepoCommit` records under that policy.

A writer's ability to sign a commit does not by itself permit publication to every ref. Ref publication is a separate authorization check.

### 6.4 Per-ref writers

`per_ref_permissions` restricts or delegates mutable ref authority.

Each entry contains:

- a valid exact ref name or namespace-prefix pattern;
- a complete writer allowlist for that match.

The selected entry replaces, rather than augments, the global writer set for ref publication.

### 6.5 Tag creators

`tag_creators` is an additional requirement for creation of `refs/tags/*`.

A tag creator must also pass the normal resolved ref-write permission for the exact tag name.

Membership in `tag_creators` alone is insufficient.

### 6.6 No implicit superuser

No role is an implicit superuser.

In particular:

- administrators do not bypass ref permissions;
- global writers do not bypass a matching per-ref deny rule;
- tag creators do not bypass ref permissions;
- local repository owners do not bypass immutable authorization during audit or sync acceptance;
- the genesis creator has no perpetual authority unless retained in later policies.

## 7. Ref permission resolution

### 7.1 Inputs

Ref permission resolution takes:

```text
policy
ref_name
candidate_key_id
```

The ref name MUST already pass `FORMAT.md` validation.

### 7.2 Pattern selection

A policy ref pattern is either exact or a namespace prefix ending in `/**`.

Resolution is deterministic:

1. If an exact pattern equals `ref_name`, select it.
2. Otherwise select the matching prefix pattern with the greatest UTF-8 byte length before `/**`.
3. If no pattern matches, use `policy.writers`.
4. If the selected writer set is empty, deny every key.

At most one exact entry and at most one entry per prefix string may exist because `FORMAT.md` requires unique sorted patterns.

No union of multiple matching patterns is performed.

### 7.3 Permission predicate

```text
can_write_ref(policy, ref_name, key_id) =
    key_id is an Ed25519 key in Registry(policy)
    AND key_id not in policy.revoked_keys
    AND key_id in resolved_writer_set(policy, ref_name)
```

For tag creation:

```text
can_create_tag(policy, ref_name, key_id) =
    ref_name begins with "refs/tags/"
    AND can_write_ref(policy, ref_name, key_id)
    AND key_id in policy.tag_creators
```

### 7.4 Examples

Given:

```text
writers = {A, B}
per_ref_permissions = {
    "refs/heads/main"            -> {A},
    "refs/heads/contributors/**" -> {B, C},
    "refs/tags/**"               -> {A, D}
}
tag_creators = {A, D}
```

Results:

- `A` can update `refs/heads/main`.
- `B` cannot update `refs/heads/main`, despite being a global writer.
- `B` and `C` can update `refs/heads/contributors/alice`.
- `A` cannot update the contributor branch unless listed in the matching rule.
- `D` can create `refs/tags/v1` because it satisfies both checks.
- `B` cannot create the tag because the matching tag rule excludes it and it is not a tag creator.
- `A` and `B` can update a ref with no matching rule because the global writer set applies.

## 8. ObjectVersion authorization semantics

### 8.1 Provenance record

An `ObjectVersion` signature authenticates authorship of an immutable logical version. It is not, by itself, a repository state transition.

A valid detached `ObjectVersion` may exist while unreachable from every ref.

### 8.2 Signer requirements

An `ObjectVersion` signer MUST:

- be an Ed25519 key known in the effective historical registry required to resolve the record;
- match `author_key_id`;
- produce a strict valid signature;
- sign a payload bound to the correct `repository_id`.

The signer is not required to be a current global writer merely to create or store the detached record.

This permits:

- provenance-only author keys;
- externally prepared candidate versions;
- review before publication;
- merge of contributor work through an authorized commit publisher.

### 8.3 Authority to make an ObjectVersion current

Authority to make an ObjectVersion current comes from the authorized `RepoCommit` transition and authorized `RefUpdate`, not from the ObjectVersion author.

The commit signer accepts responsibility for selecting the VersionId into branch state.

### 8.4 Revoked ObjectVersion signer

A valid ObjectVersion signed by a revoked key MAY remain historically reachable and MAY be reused as immutable content evidence.

Revocation does not invalidate its signature.

A current authorized commit publisher may choose to point state to such a historical VersionId. The policy engine evaluates the commit publisher's authority, not a claimed creation timestamp in the ObjectVersion.

Applications MAY impose additional content-review policy, but such policy is outside EternalCore v4 core authorization and MUST NOT be presented as format-level validity.

## 9. RepoCommit authorization

### 9.1 Structural validation first

Before authorization, a candidate `RepoCommit` must pass:

- deterministic decoding;
- RecordId recomputation;
- strict signature verification;
- repository identity checks;
- parent resolution;
- state transition recomputation;
- policy and keyring reference resolution;
- all `FORMAT.md` invariants.

Authorization never repairs an invalid state transition.

### 9.2 Genesis commit

The repository genesis commit is the unique no-parent commit accepted by bootstrap.

It MUST:

- use the empty SMT root as baseline and result unless bootstrap explicitly creates objects under a future format revision;
- name `RepositoryGenesis.initial_policy_id`;
- name `RepositoryGenesis.initial_keyring_id`;
- be signed by the genesis creator;
- contain no extra parents;
- pass the initialization transaction in `TRANSACTIONS.md`.

No later no-parent commit is valid.

### 9.3 Regular content commit

A non-merge regular content commit MUST:

- have exactly one parent;
- keep `policy_id` equal to the first parent's `policy_id`;
- keep `keyring_id` equal to the first parent's `keyring_id`;
- contain one or more valid object changes;
- be signed by a key in the first-parent policy's global `writers` set;
- not be signed by a key in that policy's `revoked_keys`.

Per-ref permissions are not evaluated at commit creation because a commit does not name a ref. They are evaluated when a `RefUpdate` publishes the commit.

### 9.4 Merge commit

A merge commit MUST:

- have at least two parents;
- use parent 0 as the state and authorization baseline;
- keep `policy_id` equal to parent 0's policy ID;
- keep `keyring_id` equal to parent 0's keyring ID;
- be signed by an active global writer under parent 0's policy;
- satisfy the three-way merge and state-transition rules defined by architecture and transaction specifications.

Policies and keyrings from additional parents do not become authoritative merely because their commits are named as merge parents.

### 9.5 Policy administrative commit

A policy administrative commit MUST:

- have exactly one parent;
- have `changes = []`;
- preserve the parent's `object_state_root`;
- preserve the parent's `keyring_id`;
- set `policy_id` to exactly one valid child policy of the parent's policy;
- be signed by the same `author_key_id` that signed the new PolicyRecord;
- be signed by an administrator authorized under the parent policy;
- not simultaneously change keyring state.

Authorization is evaluated against the parent policy, never the new policy.

This prevents self-authorization.

### 9.6 Keyring administrative commit

A keyring administrative commit MUST:

- have exactly one parent;
- have `changes = []`;
- preserve the parent's `object_state_root`;
- preserve the parent's `policy_id`;
- set `keyring_id` to exactly one valid child keyring of the parent's keyring;
- be signed by the same `author_key_id` that signed the new KeyringRecord;
- be signed by an administrator authorized under the parent policy;
- not simultaneously change policy state.

Format v1 has no separate key-manager role. All KeyringRecord transitions require administrator authority.

### 9.7 Forbidden mixed commits

A format-v1 commit is invalid if it combines any of the following:

- object changes and a policy transition;
- object changes and a keyring transition;
- a policy transition and a keyring transition;
- merge parents and a policy transition;
- merge parents and a keyring transition.

Administrative transitions are isolated in dedicated one-parent, empty-change commits for unambiguous review and audit.

### 9.8 Commit signer and ref updater

The RepoCommit signer and RefUpdate signer MAY differ.

Both are checked independently:

- the commit signer must satisfy commit-type authority;
- the RefUpdate signer must satisfy the resolved ref permission.

This permits an authorized release manager to publish a commit signed by another authorized writer without transferring signing keys.

## 10. KeyringRecord authorization

### 10.1 Signer authority

A KeyringRecord transition must be signed by an active administrator under the policy selected by the first parent commit of the administrative commit that publishes it.

There is no independent `key_manager` role in format v1.

### 10.2 Chain continuity

A new KeyringRecord MUST:

- reference the current first-parent keyring as `previous_keyring_id`;
- preserve repository identity;
- satisfy all cryptographic lifecycle rules in `CRYPTO.md`;
- be published only through a valid keyring administrative commit.

A valid but unpublished KeyringRecord has no branch authority.

### 10.3 Key-slot recipient authority

Being named as an X25519 recipient or password-slot holder grants only the ability to unwrap the specific secret.

It grants no authority to:

- sign ObjectVersions;
- sign commits;
- update refs;
- administer policy;
- administer keyrings.

### 10.4 DEK rotation publication

Physical creation of new EncodedChunks under a new DEK epoch may occur before the new keyring becomes authoritative, as required by `CRYPTO.md` and `TRANSACTIONS.md`.

The new epoch becomes the branch's accepted encryption state only after the keyring administrative commit and ref update are authorized and durable.

## 11. RefUpdate authorization

### 11.1 RefUpdate validation layers

A candidate RefUpdate must pass:

1. deterministic decoding and schema validation;
2. RefUpdateId recomputation;
3. strict signature verification;
4. predecessor-chain validation;
5. sequence validation;
6. target-commit validation or deletion rules;
7. governing-policy resolution;
8. ref permission evaluation;
9. namespace-specific rules;
10. predecessor-ID CAS at publication.

### 11.2 Existing live ref

For an existing ref whose current RefUpdate has a non-null target, the governing policy is the policy named by that target commit.

The candidate signer must pass `can_write_ref(governing_policy, ref_name, signer)`.

### 11.3 Deleted ref and recreation

A deletion RefUpdate has `target_commit_id = null` but remains the mutable ref file's value and part of the predecessor chain.

For a candidate extending a deleted ref, the governing policy is resolved by walking backward through `previous_ref_update_id` until the most recent non-null target commit is found.

The recreation candidate MUST:

- name the deletion RefUpdate as its predecessor;
- increment sequence exactly;
- use the same ref name;
- pass the governing historical policy's ref permission;
- target an anchored valid commit.

A deleted ref is therefore not equivalent to a never-created ref.

### 11.4 First creation of a non-bootstrap ref

A first-creation RefUpdate has:

- `previous_ref_update_id = null`;
- `sequence = 1`;
- a non-null target commit.

Except for the bootstrap main ref, its target commit MUST be anchored in the existing repository authority graph.

A target is anchored when at least one of the following holds:

- it is already reachable from a live authorized ref;
- one of its ancestors is reachable from a live authorized ref and every transition from that ancestor to the target validates under this document;
- it is reachable from a retained authenticated ref history explicitly accepted by the local repository.

An attacker cannot create a disconnected commit graph with its own policy and gain authority by pointing a new ref at it.

For first creation, the governing policy is the target commit's validated policy after the complete anchored ancestry has been checked.

### 11.5 Bootstrap main ref

The initial `refs/heads/main` RefUpdate is a bootstrap exception.

It MUST:

- be created in the repository initialization transaction;
- have no predecessor and sequence 1;
- target the validated genesis commit;
- be signed by the genesis creator;
- use the exact repository ID from genesis.

No other ref receives this exception.

### 11.6 Branch update

A branch update under `refs/heads/*` requires:

- exact predecessor RefUpdateId;
- exact next sequence;
- non-null target commit;
- target graph completeness or valid partial-clone promises;
- governing-policy ref permission;
- commit-transition authorization.

Fast-forward ancestry is not required by the core format because explicit branch rewrites can be represented by a new signed RefUpdate. Applications SHOULD warn on non-fast-forward updates, but MUST preserve and audit the predecessor chain.

### 11.7 Branch deletion

A branch deletion requires:

- an existing live branch;
- target null;
- exact predecessor and next sequence;
- authorization under the current target commit's policy;
- a signer passing the branch's resolved ref permission.

The mutable ref file remains and points to the deletion RefUpdate, as fixed by `FORMAT.md`.

### 11.8 Tag creation and immutability

A tag creation MUST:

- use `refs/tags/*`;
- have no predecessor;
- have sequence 1;
- have a non-null target;
- target an anchored valid commit;
- be signed by a key that passes both `can_write_ref` and `tag_creators` membership under the governing target policy.

Any tag RefUpdate with a predecessor is invalid.

Tag deletion, movement, and recreation are forbidden in format v1, including by an administrator.

### 11.9 Pins and merge requests

`refs/pins/*` and `refs/merge-requests/*` use the same predecessor-linked CAS and ref permission resolution as branches.

They may be updated or deleted unless a future format profile defines stricter semantics.

A pin affects GC reachability but does not grant additional authorization.

A merge-request ref is a proposal pointer; merging it still requires an authorized merge commit and update of the destination ref.

### 11.10 Ref signer and target policy changes

For an existing ref, ref-update authority is evaluated against the predecessor ref's governing policy, not solely against the candidate target commit's new policy.

Therefore a candidate policy cannot grant its own publisher permission to install itself.

For a policy administrative commit:

- the policy transition is authorized under the first parent policy;
- the RefUpdate that publishes it is authorized under the predecessor ref's policy;
- only after publication does the new policy govern the next transition.

## 12. Branch-local policy evolution

### 12.1 Policy is part of commit state

Every RepoCommit names one PolicyId. Different branches may legitimately point to commits with different policy descendants.

There is no repository-global mutable policy file.

### 12.2 First-parent rule

For every non-genesis commit, authority is evaluated against parent 0's policy.

Additional merge parents provide history but do not provide authority.

### 12.3 Merging branches with divergent policy

A merge commit MUST preserve parent 0's policy and keyring.

The policy from another parent is not automatically combined, selected, or adopted.

To adopt an equivalent policy change from another branch, an administrator on the destination branch must create a new PolicyRecord that validly extends the destination's current policy and then publish a separate policy administrative commit.

### 12.4 Policy forks

Two different PolicyRecords may validly extend the same predecessor on different branches. They are distinct policy forks.

Neither invalidates the other. Each governs only histories that explicitly select it through authorized commits and refs.

A policy chain is linear along a commit's first-parent history even when the repository commit graph branches.

### 12.5 No policy merge record

Format v1 has no multi-parent PolicyRecord and no automatic policy merge.

Administrative intent must be restated in a new complete policy snapshot extending the destination branch's current policy.

## 13. Revocation and historical authorization

### 13.1 Revocation effective point

A revocation becomes authoritative on a branch only when:

1. the revoking PolicyRecord is valid under the previous policy;
2. a valid policy administrative commit selects it;
3. an authorized RefUpdate publishes that commit.

The signed timestamp is not the effective point.

### 13.2 Future authorization

After the revoking policy is authoritative on a branch, the revoked key MUST NOT authorize later:

- PolicyRecords;
- KeyringRecords;
- regular commits;
- merge commits;
- administrative commits;
- RefUpdates;
- tag creation.

### 13.3 Historical validity

A historical record signed by a now-revoked key remains mathematically valid.

It remains historically authorized only if its position in the validated commit/ref chain shows that it was published under a policy that still allowed the key.

A claimed timestamp before revocation is insufficient.

### 13.4 Detached records after revocation

A detached RepoCommit or RefUpdate signed by a revoked key cannot gain authority by being received later, even if its timestamp predates revocation.

Authorization is evaluated against the actual predecessor state at attempted publication.

### 13.5 Compromise response

When a signing key is suspected compromised:

1. use another current administrator to publish a policy revocation;
2. remove the key from all active roles and ref permission sets;
3. introduce replacement keys as needed;
4. inspect ref histories for unauthorized transitions before the revocation point;
5. publish corrective commits or ref updates without deleting evidence;
6. distribute the new authoritative ref tip through trusted channels.

If no uncompromised administrator remains, EternalCore core has no recovery override.

## 14. Policy and transaction interaction

### 14.1 Preparation outside writer lock

A client may prepare content, signatures, and candidate records outside the writer lock.

Preparation does not reserve authority.

### 14.2 Publication-time revalidation

Immediately before logical publication, while holding the writer lock, the implementation MUST re-read and revalidate:

- the current ref pointer;
- expected predecessor RefUpdateId;
- base RepoCommitId;
- base PolicyId and policy chain;
- base KeyringId when relevant;
- commit signer authority;
- ref signer authority;
- policy/keyring transition continuity;
- target graph completeness.

Any policy or ref change invalidating the prepared candidate aborts publication.

### 14.3 Orphan records

Unauthorized or stale candidate records may remain physically stored as unreachable immutable records.

Their presence does not grant authority. They may later be collected by GC.

### 14.4 Ambiguous result

When publication outcome is ambiguous, the client determines result from the authenticated ref predecessor chain, not by re-signing with a different key or trusting local intent.

### 14.5 Batch transaction

A batch transaction produces one RepoCommit and one RefUpdate.

All object changes share one first-parent policy evaluation. If policy changes before publication, the entire batch aborts.

A batch MUST NOT mix administrative policy/keyring changes with object changes.

## 15. Synchronization and remote acceptance

### 15.1 Transport authentication is separate

Transport authentication proves possession of a session identity. It does not grant repository mutation authority.

A session that can transfer records may still be denied ref publication.

### 15.2 Metadata visibility

EternalCore v4 core defines write authorization, not metadata read ACLs.

A node admitted to metadata-complete synchronization can observe:

- ObjectIds;
- metadata;
- relations;
- commit topology;
- refs;
- policy history;
- public-key history;
- keyring structure excluding unavailable wrapped-secret plaintext.

Payload encryption protects content bytes, not this metadata.

### 15.3 Incoming graph validation

Before publishing an incoming ref, the receiver MUST validate:

- repository and federation identity as applicable;
- genesis anchor;
- every required policy transition;
- every required public key;
- every signed record;
- commit state transitions;
- commit-type authority;
- ref predecessor and sequence;
- ref permission;
- partial-clone promise closure;
- local predecessor-ID CAS.

A sender's claim that a key is trusted is ignored.

### 15.4 Remote-created branch

Creation of a remote branch uses the same first-creation anchored-history rule as local creation.

The receiver MUST NOT accept a disconnected target graph merely because the remote signed both its policy and ref update.

### 15.5 Divergent ref

If the expected predecessor does not equal the receiver's current RefUpdateId, publication fails with `RefCasMismatch`.

The receiver may retain imported immutable records, but MUST NOT silently create a new branch unless the caller explicitly requests a branch-creation operation and that creation is separately authorized.

### 15.6 Partial clone

A metadata-complete partial clone MUST possess all policy evidence needed to validate its current refs.

Content promises do not weaken authorization checks.

A missing payload chunk may be promised. A missing policy, public key, commit, SMT node, ObjectVersion, ContentManifest, or RefUpdate required by the current state is not a valid partial-clone omission.

## 16. Local configuration and caches

### 16.1 Non-authoritative files

The following MUST NOT grant repository authority:

- `.eternal/config.toml`;
- local contact lists;
- local remote configuration;
- `trusted_keys/`;
- OS usernames;
- cached role tables;
- cached ref permissions;
- UI account names.

### 16.2 trusted_keys cache

A `trusted_keys/` directory MAY cache public keys for performance or inspection.

Every cached key must be reproducible from genesis and PolicyRecord ancestry. On mismatch, immutable records win and the cache is rebuilt or rejected.

### 16.3 Authorization cache keying

Authorization caches MUST be keyed by immutable context, at minimum:

```text
(repository_id, PolicyId, operation, subject KeyId, optional ref_name)
```

A cache entry from one PolicyId MUST NOT be reused for another PolicyId.

Revocation requires no cache invalidation mechanism beyond changing PolicyId, provided caches are correctly keyed.

### 16.4 Cache result classes

Caches may store:

- valid policy ancestry;
- effective key registry;
- resolved ref writer set;
- role membership;
- validated transition results.

Caches must not convert an unresolved or incomplete graph into an allow result.

## 17. Deterministic validation algorithms

### 17.1 Validate policy chain

```text
validate_policy_chain(genesis, target_policy_id):
    load target policy ancestry to initial policy
    reject cycle, missing predecessor, duplicate PolicyId, or excessive depth
    validate initial policy against genesis creator
    registry = {genesis creator key}
    revoked = empty

    for each later policy in forward order:
        verify deterministic payload and detached signature
        require previous ID and sequence continuity
        require author is active administrator in previous policy
        validate introduced keys against registry
        registry = registry union introduced keys
        require revoked set is cumulative
        require all role members are registered Ed25519 keys
        require no revoked key in an active role/permission
        require at least one active administrator
        accept policy snapshot

    return ValidatedPolicy(target, registry)
```

Implementations MUST enforce configured but safe maximum graph depths and report resource-limit errors rather than recurse without bound.

### 17.2 Authorize regular commit

```text
authorize_regular_commit(parent, candidate):
    policy = validated_policy(parent.policy_id)
    require candidate has exactly one parent
    require candidate.policy_id == parent.policy_id
    require candidate.keyring_id == parent.keyring_id
    require candidate.changes is non-empty
    require candidate.author in policy.writers
    require candidate.author not revoked
    require valid state transition
```

### 17.3 Authorize merge commit

```text
authorize_merge_commit(parent0, candidate):
    policy = validated_policy(parent0.policy_id)
    require candidate has at least two parents
    require candidate.policy_id == parent0.policy_id
    require candidate.keyring_id == parent0.keyring_id
    require candidate.author in policy.writers
    require candidate.author not revoked
    require valid baseline and merge transition
```

### 17.4 Authorize policy commit

```text
authorize_policy_commit(parent, candidate, new_policy):
    old_policy = validated_policy(parent.policy_id)
    validate new_policy as direct child of old_policy
    require one parent
    require empty changes
    require unchanged state root
    require unchanged keyring
    require candidate.policy_id == new_policy.id
    require candidate.author == new_policy.author
    require candidate.author was administrator in old_policy
```

### 17.5 Authorize keyring commit

```text
authorize_keyring_commit(parent, candidate, new_keyring):
    policy = validated_policy(parent.policy_id)
    validate new_keyring as direct child of parent.keyring
    require one parent
    require empty changes
    require unchanged state root
    require unchanged policy
    require candidate.keyring_id == new_keyring.id
    require candidate.author == new_keyring.author
    require candidate.author in policy.administrators
    require candidate.author not revoked
```

### 17.6 Authorize RefUpdate

```text
authorize_ref_update(current_ref, candidate):
    require same ref_name
    require exact predecessor and sequence
    resolve governing policy from current or historical non-null target
    validate candidate target commit when non-null

    if tag namespace:
        require first creation only
        require can_create_tag(governing policy, ref, candidate.author)
    else:
        require can_write_ref(governing policy, ref, candidate.author)

    require namespace lifecycle rules
    require CAS against current RefUpdateId at publication
```

First creation and bootstrap use the special rules in Section 11.

## 18. Policy construction rules

### 18.1 Complete snapshots

Policy editing tools MUST display the complete resulting snapshot before signing, including:

- all administrators;
- all global writers;
- every per-ref pattern and exact writer set;
- all tag creators;
- all newly introduced keys;
- the complete cumulative revoked set.

A CLI MUST NOT hide carried-forward authority behind an implicit merge with the old policy.

### 18.2 Safe defaults

Repository initialization SHOULD create:

- at least two administrator keys when operationally possible;
- a narrowly scoped global writer set;
- an exact rule for `refs/heads/main`;
- a contributor namespace such as `refs/heads/contributors/**` when needed;
- a restricted tag namespace;
- no broad wildcard beyond the fixed `/**` grammar.

These are operational recommendations, not byte-level requirements.

### 18.3 Separation of duties

For high-assurance deployments, the same key SHOULD NOT simultaneously be:

- the only administrator;
- the only global writer;
- the only main-branch publisher;
- the only tag creator;
- the only decryption recipient.

The core supports overlap but does not require it.

### 18.4 Offline administrator keys

At least one administrator key SHOULD be kept offline or in a hardware-backed provider.

Routine object commits and branch updates SHOULD use separate writer keys.

### 18.5 Policy review output

Before signing a policy transition, tools SHOULD render a deterministic semantic diff:

```text
introduced keys
added administrators
removed administrators
added writers
removed writers
changed ref rules
added tag creators
removed tag creators
new revocations
```

The displayed diff is advisory. The signature always covers the complete deterministic payload.

## 19. CLI behavior

A conforming CLI should expose at least:

```text
eternal key list
eternal key introduce <public-key>
eternal key revoke <key-id>
eternal policy show [--at <commit-or-policy>]
eternal policy diff <old> <new>
eternal policy set-admin <key-id> <on|off>
eternal policy set-writer <key-id> <on|off>
eternal policy set-ref <pattern> <key-id>...
eternal policy remove-ref <pattern>
eternal policy set-tag-creator <key-id> <on|off>
eternal policy publish -m <message>
eternal auth explain <operation> [arguments]
```

The implementation MAY stage a candidate policy in local memory or a temporary non-authoritative file, but publication must create one signed PolicyRecord, one administrative RepoCommit, and one RefUpdate transaction.

### 19.1 Explain mode

`auth explain` SHOULD report:

- governing PolicyId;
- subject KeyId;
- operation class;
- matched ref pattern, if any;
- resolved writer set source;
- role membership;
- revocation status;
- final allow or deny reason.

It MUST NOT expose private keys, passwords, DEKs, ContentIdKey, or decrypted content.

### 19.2 Confirmation

Policy publication tools SHOULD require explicit confirmation when a change:

- removes an administrator;
- revokes a key;
- changes `refs/heads/main` permissions;
- creates a deny-all rule;
- removes every global writer;
- changes tag creators;
- introduces a broad namespace rule.

The core library still enforces deterministic validity independent of UI confirmation.

## 20. Library interfaces

Recommended core interfaces:

```rust
pub struct ValidatedPolicy {
    pub policy_id: PolicyId,
    pub policy_sequence: u64,
    pub registry: Arc<KeyRegistry>,
    pub administrators: BTreeSet<KeyId>,
    pub writers: BTreeSet<KeyId>,
    pub per_ref_permissions: Vec<RefPermission>,
    pub tag_creators: BTreeSet<KeyId>,
    pub revoked_keys: BTreeSet<KeyId>,
}

pub enum CommitKind {
    Genesis,
    Regular,
    Merge,
    PolicyAdministrative,
    KeyringAdministrative,
}

pub enum RefOperation {
    Create,
    Update,
    Delete,
    Recreate,
    CreateTag,
}

pub struct AuthorizationContext<'a> {
    pub repository_id: RepositoryId,
    pub policy: &'a ValidatedPolicy,
    pub subject: KeyId,
    pub ref_name: Option<&'a RefName>,
}

pub trait PolicyEvaluator {
    fn validate_chain(
        &self,
        genesis: &SignedRepositoryGenesis,
        target: PolicyId,
    ) -> Result<ValidatedPolicy>;

    fn authorize_commit(
        &self,
        commit: &SignedRepoCommit,
        graph: &dyn RepositoryGraph,
    ) -> Result<CommitKind>;

    fn authorize_ref_update(
        &self,
        candidate: &SignedRefUpdate,
        current: Option<&SignedRefUpdate>,
        graph: &dyn RepositoryGraph,
    ) -> Result<()>;

    fn can_write_ref(
        &self,
        policy: &ValidatedPolicy,
        ref_name: &RefName,
        subject: KeyId,
    ) -> AuthorizationDecision;
}
```

The policy evaluator MUST be pure with respect to authorization: it may read immutable graph data and caches keyed by immutable IDs, but must not consult mutable local preferences.

## 21. Error classification

Authorization errors MUST be distinguishable from corruption and cryptographic errors.

Recommended errors include:

```rust
pub enum PolicyError {
    GenesisPolicyMismatch,
    PolicyPredecessorMissing,
    PolicyCycle,
    PolicySequenceMismatch,
    PolicySequenceOverflow,
    PolicySignatureInvalid,
    PolicyAuthorUnknown,
    PolicyAuthorNotAdministrator,
    PolicyAuthorRevoked,
    KeyIdMismatch,
    KeyRedefinition,
    InvalidRoleKeyAlgorithm,
    UnknownRoleKey,
    RevocationNotCumulative,
    RevokedKeyStillActive,
    NoActiveAdministrator,
    RefPatternInvalid,
    RefPermissionDenied,
    TagCreatorDenied,
    TagMutationForbidden,
    RefPredecessorMismatch,
    RefSequenceMismatch,
    RefCasMismatch,
    RefTargetUnanchored,
    CommitSignerNotWriter,
    CommitSignerRevoked,
    CommitKindInvalid,
    MixedAdministrativeCommit,
    PolicySelfAuthorization,
    KeyringTransitionUnauthorized,
    HistoricalAuthorizationUnknown,
}
```

A caller must be able to distinguish:

- malformed data;
- missing graph data;
- bad signature;
- unknown key;
- valid signature but denied authority;
- CAS conflict;
- unsupported operation.

## 22. Audit requirements

A full authorization audit MUST verify, for every retained authoritative ref:

1. RepositoryGenesis signature and creator KeyId;
2. initial PolicyId and KeyringId binding;
3. complete required public-key registry;
4. every policy transition in forward order;
5. cumulative revocation;
6. every KeyringRecord transition and administrator authority;
7. every RepoCommit signature and commit-kind authority;
8. every RefUpdate signature, predecessor, sequence, lifecycle rule, and ref permission;
9. every tag's create-only history;
10. every current branch's policy and keyring selection;
11. merge first-parent policy behavior;
12. absence of self-authorizing transitions.

Audit output SHOULD identify the exact immutable IDs and governing PolicyId for each failure.

An audit MUST NOT classify a valid historical signature as invalid merely because the key is revoked in a later policy.

## 23. Mandatory tests

### 23.1 Policy-chain tests

- initial policy validates only against the genesis creator;
- wrong initial PolicyId is rejected;
- sequence skip, repeat, and overflow are rejected;
- policy predecessor cycles are rejected;
- non-administrator policy signer is rejected;
- revoked administrator is rejected;
- newly introduced administrator cannot authorize the policy that introduces it;
- key redefinition is rejected;
- X25519 key in a signing role is rejected;
- non-cumulative revocation is rejected;
- revoked key in any active role is rejected;
- zero-administrator policy is rejected;
- zero-writer policy is accepted;
- exact carried-forward complete snapshot semantics are preserved.

### 23.2 Ref-pattern tests

- exact match overrides every prefix;
- longest prefix wins;
- no match falls back to global writers;
- empty matching allowlist denies all;
- global writer is denied by a restrictive matching rule;
- administrator has no implicit ref permission;
- tag creator without ref permission is denied;
- ref writer without tag-creator role is denied for tag creation.

### 23.3 Commit tests

- regular commit by global writer is accepted;
- regular commit by per-ref-only key but not global writer is rejected at commit authority;
- commit by revoked writer is rejected;
- merge uses parent 0 policy only;
- additional parent policy does not grant authority;
- regular commit changing policy is rejected;
- regular commit changing keyring is rejected;
- policy administrative commit with object changes is rejected;
- policy administrative commit changing keyring is rejected;
- keyring administrative commit changing policy is rejected;
- administrative commit signer must equal record signer;
- policy transition is checked under old policy;
- detached ObjectVersion by a non-writer known key can be selected by an authorized commit.

### 23.4 RefUpdate tests

- exact predecessor and sequence are required;
- RefUpdateId CAS prevents ABA;
- existing ref uses predecessor target policy;
- policy update cannot self-authorize its RefUpdate;
- branch deletion produces a null-target successor;
- recreation extends deletion and uses last non-null governing policy;
- first branch creation from anchored history is accepted;
- disconnected self-governed branch creation is rejected;
- bootstrap main exception works only during initialization;
- tag creation succeeds once;
- tag movement, deletion, and recreation are rejected;
- pin and merge-request lifecycle follows general rules.

### 23.5 Revocation tests

- old signatures remain cryptographically valid;
- historical transitions remain authorized when published before revocation in graph order;
- claimed pre-revocation timestamp does not authorize a later publication;
- detached commit by revoked key cannot be published;
- revocation on one branch does not silently alter a divergent branch until that branch adopts a descendant policy;
- same public key cannot be un-revoked.

### 23.6 Synchronization tests

- remote valid signature without authority is rejected;
- remote `trusted` claim is ignored;
- imported graph cannot replace genesis anchor;
- missing policy evidence blocks ref publication;
- metadata-complete partial clone validates policy without payload chunks;
- CAS failure leaves immutable records unreachable;
- remote cannot auto-create conflict branch without explicit authorized request.

### 23.7 Cache tests

- deleting policy cache does not change decisions;
- corrupt cache is rejected and rebuilt;
- cache keyed to old PolicyId is not reused after policy transition;
- local `trusted_keys/` addition does not grant authority;
- local config cannot add an administrator or writer.

### 23.8 Property tests

Property testing SHOULD cover:

- deterministic ref-pattern resolution;
- role sets as canonical mathematical sets;
- revocation monotonicity;
- no allow result for a revoked key;
- no policy transition authorized by a key introduced only in that transition;
- no administrative commit changes object state;
- no tag has more than one RefUpdate;
- every accepted non-bootstrap ref graph is anchored.

### 23.9 Fuzzing

Fuzz targets SHOULD include:

- arbitrary policy ancestry graphs;
- cycles and extremely deep chains;
- duplicate and unsorted key entries;
- overlapping ref patterns;
- malformed or adversarial ref names;
- mixed commit classifications;
- deleted-ref predecessor walks;
- unknown or mismatched key algorithms;
- resource-exhaustion attempts.

Fuzzing must assert no panic, unbounded recursion, or authorization allow on incomplete evidence.

## 24. Resource limits

Implementations MUST enforce configurable safe limits for policy evaluation, including:

- maximum policy ancestry depth loaded in one operation;
- maximum introduced keys per policy;
- maximum total known keys;
- maximum administrators, writers, tag creators, and revoked keys;
- maximum per-ref permission entries;
- maximum predecessor depth traversed for a deleted ref;
- maximum commit ancestry searched for branch anchoring.

Exceeding a resource limit returns a fail-closed error. It MUST NOT fall back to an allow decision.

Limits are implementation safety controls and do not alter canonical record validity. A repository exceeding local limits may require an explicitly higher configured limit or offline audit tooling.

## 25. Operational guidance

### 25.1 Recommended minimum authority layout

A production repository should use:

- two or more administrator keys;
- at least one offline administrator;
- separate routine writer keys;
- an exact `refs/heads/main` allowlist;
- contributor branches under a distinct prefix;
- restricted tag creators;
- no administrator key used as a network-service hot key unless necessary.

### 25.2 Main branch

`refs/heads/main` should use an exact per-ref rule rather than relying on global writers.

This prevents every contributor with commit-authority from directly publishing to the main branch.

### 25.3 Contributor workflow

A typical policy may grant:

- global commit-authority to contributor signing keys;
- contributor-specific ref permission under `refs/heads/contributors/**`;
- main publication only to release-manager keys.

The contributor signs ObjectVersions and RepoCommits, publishes to a contributor branch, and a main-branch publisher reviews and merges.

### 25.4 Revocation readiness

Administrators should keep:

- current policy IDs;
- offline copies of administrator public keys;
- authenticated ref tips;
- documented key ownership;
- tested revocation procedures.

Private-key backup and recovery remain operational responsibilities. The repository cannot reconstruct a lost private key.

## 26. Conformance checklist

An implementation is policy-conformant only if it satisfies all of the following:

- [ ] Genesis is the sole trust bootstrap.
- [ ] Policy records are complete snapshots.
- [ ] Public-key history is append-only.
- [ ] Policy transitions use previous-policy administrator authority.
- [ ] Revocation is cumulative and timestamp-independent.
- [ ] At least one active administrator remains.
- [ ] Only Ed25519 keys hold signing roles.
- [ ] Administrators have no implicit ref-write authority.
- [ ] Exact/longest-prefix ref resolution is deterministic.
- [ ] Matching per-ref rules replace global writers.
- [ ] Tag creation requires both permissions and is create-only.
- [ ] Regular and merge commits require global writer authority.
- [ ] Administrative commits are isolated and empty-change.
- [ ] Policy and keyring changes cannot be combined.
- [ ] Commit and ref signers are checked independently.
- [ ] Existing refs use predecessor-state policy.
- [ ] Deleted-ref recreation uses the last non-null governing policy.
- [ ] First-created refs require anchored history.
- [ ] Merge authority comes only from parent 0.
- [ ] Local config and caches never grant authority.
- [ ] Remote records undergo the same policy checks as local records.
- [ ] Publication-time revalidation occurs under the writer lock.
- [ ] Every deny condition fails closed with a specific error.

## 27. Final invariant

The governing invariant of EternalCore authorization is:

> No key gains authority from possession, a label, a timestamp, a local configuration entry, a valid signature alone, or a policy it is attempting to introduce. Authority exists only as an explicitly validated capability in the immutable policy selected by the already-authoritative predecessor history, and every state change must separately pass commit authorization, ref authorization, and predecessor-linked atomic publication.
