# Classic-retirement composition derivative — NOT YET QUALIFIED

This isolated candidate derives from M2 controller `b8bbb84`. It does not
change the accepted M2 worktree, result, or runtime claims. The derivative Docket
runtime is now candidate `6c57926` (adds migration-free `show-read-only` to
the c49 lineage); AG runtime is newly pinned to `bf6adde` rather than
inheriting acceptance from `837de28`.

`build_bookworm_fixture.py` rebuilds the composition driver against that AG
revision. `build_retirement_executor.py` reuses its exact offline Bookworm
image, source export, vendor identity, command assembly and deterministic
packaging mechanics to build a separate feature-enabled `ag-effectd` package
twice. The latter installs no service, configuration or mutable state. Its
receipt is build evidence, not execution or package-installation acceptance.

Each build now streams stdout/stderr to an exclusive durable output log before
checking its exit code, with a separate terminal record. A failed later build
does not delete earlier logs. Scratch compilation files remain temporary; logs
and partial output custody remain in the named occurrence for reconciliation.
This corrects an independent-review finding in the first derivative candidate;
the already-started 001 occurrence remains attached to its original source.

Executor package acceptance additionally requires an independent inspection of
the actual archive's closed binary-only layout, ownership/modes, control fields,
binary and package hashes against the receipt, source/tree/vendor/image pins,
and both retained build logs. The receipt does not authenticate itself. No
automatic runner pin is generated from an unreviewed receipt.

Pending: independently review the derivative builders, build and inspect their
actual artifacts, pin the final corrected NQ native package and AG package in
a separate derivative harness, then run the affected local and two-VM witnesses.
No VM launch is authorized by merely producing a package. Original package
digests and qualification-result identities must not be presented as accepting
these new artifacts. Root owns integrated dependency pins and final acceptance.

The two-build occurrence001 on Docketc49 is retained as intermediate evidence.
The new6c package is candidate-only until the exact read-only implementation's
four gates and independent review close. A build is permitted against its frozen
interface while acceptance completes; it does not close that acceptance gate.
