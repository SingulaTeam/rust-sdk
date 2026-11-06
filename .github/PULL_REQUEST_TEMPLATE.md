<!--
Thanks for the pull request. A reviewer reads this before the code, so say
what they need to know. Delete any section that does not apply.

A vulnerability fix does not belong here: see SECURITY.md.
-->

## What changes

<!-- One or two sentences. What can someone do after this that they could not before, or what now behaves differently? -->

## Why

<!-- The problem, or the issue this closes: "Closes #123". -->

## How it was checked

<!-- Tests added or changed, and anything run by hand: live tests, another implementation, a real Control Plane. -->

## Wire formats

<!--
Does this change anything another implementation must agree with — a digest,
a signature, an encoding, a proof, a contract call? If so: which, and where
the test vectors come from. Vectors must come from another implementation,
not from this crate.
-->

- [ ] No wire format changes
- [ ] Wire format changes, with vectors from: <!-- the Control Plane, viem, the JS client… -->

## Checklist

- [ ] `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` pass
- [ ] `cargo test --all-features` passes
- [ ] New public items are documented
- [ ] `CHANGELOG.md` has an entry under *Unreleased*, if users would notice the change
