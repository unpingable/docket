# Classic-retirement composition derivative — NOT YET QUALIFIED

This isolated candidate derives from M2 controller `b8bbb84`. It does not
change the accepted M2 worktree, result, or runtime claims. The fixed Docket
runtime remains `c49ad8d`; AG runtime is newly pinned to `bf6adde` rather than
inheriting acceptance from `837de28`.

`build_bookworm_fixture.py` rebuilds the composition driver against that AG
revision. `build_retirement_executor.py` reuses its exact offline Bookworm
image, source export, vendor identity, command assembly and deterministic
packaging mechanics to build a separate feature-enabled `ag-effectd` package
twice. The latter installs no service, configuration or mutable state. Its
receipt is build evidence, not execution or package-installation acceptance.

Pending: independently review the derivative builders, build and inspect their
actual artifacts, pin the final corrected NQ native package and AG package in
a separate derivative harness, then run the affected local and two-VM witnesses.
No VM launch is authorized by merely producing a package. Original package
digests and qualification-result identities must not be presented as accepting
these new artifacts. Root owns integrated dependency pins and final acceptance.
