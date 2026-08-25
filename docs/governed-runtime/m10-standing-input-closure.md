# M10 standing-resolver input closure

M10 preserves the frozen execution-standing request and resolution schemas.
It adds an opt-in exact-input mode to the already-qualified external resolver
custody path:

```text
--standing-resolver-content sha256:<64 lowercase hex>
--standing-resolver-journal /absolute/create-new/path.jsonl
--standing-resolver-ttl-ms <positive decimal milliseconds>
--standing-resolver-custody-directory /absolute/private/directory
```

Supplying only the first two flags retains M9 launch-record v1 behavior.
Supplying all four selects M10. Partial combinations refuse before standing
resolution.

## Exact input set

`civil.docket.standing-resolver-input-set/v1` is canonical JCS and binds:

- the exact standing request digest and Docket-sampled historical evaluation
  time carried by request v1;
- the positive TTL transported to the standing authority;
- the configured custody-directory locator and the device, inode, mode, owner,
  group, and link count of the directory object Docket actually opened;
- the fixed request/response entry names and create-exclusive-or-byte-identical
  update rule;
- fixed argv, the two-entry child environment, `/` working directory, umask
  `0077`, and the qualified inherited-descriptor profile.

Docket opens the final custody directory without following a symlink, checks
that it is private, and passes the already-opened object at descriptor 64. The
resolver uses descriptor-relative `openat(2)` operations for the two fixed
artifacts and does not resolve the custody pathname again.

The exact child environment contains only:

```text
CIVIL_M3_DOCKET_STANDING_CUSTODY_FD=64
CIVIL_M3_STANDING_TTL_MS=<exact value>
```

Legacy executor APIs continue to inherit their original environment. The new
exact-input API also fixes the resolver child working directory and umask. It
does not claim to be a general process sandbox: descriptors inherited from the
runtime remain outside the material-input set because the frozen static
resolver implementation does not inspect them.

## Launch record v2

`civil.docket.standing-resolver-launch-record/v2` embeds the exact input set
and its SHA-256 content identity in every stage. The launch identity uses the
versioned domain `docket.governed-loop.standing-resolver-launch/v2` and binds:

- expected resolver content;
- exact AG issuance identity;
- exact request digest;
- exact standing-input-set digest.

After decoding the unchanged response v1, Docket additionally requires the
resolver's `resolved_at_unix_ms` to equal the exact request time and its
`expires_at_unix_ms` to equal that time plus the exact TTL. This validates
transport/binding without moving standing judgment into Docket.

## Boundary

The request time remains a Docket-owned system-clock observation under the
frozen standing contract. Retained evidence establishes the historical time
fact used, not clock truth or present currentness. Exact input custody does not
prove the standing answer objectively true, establish host integrity, or add
AG executable/environment semantics.
