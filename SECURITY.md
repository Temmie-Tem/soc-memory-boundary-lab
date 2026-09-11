# Security Policy

## Scope

This repository contains host-side analysis tooling, documentation, and evidence
manifests for research into the system-physical-address to DRAM mapping on one
Qualcomm SM8150 device. It does not distribute firmware, vendor binaries, or
exploits.

At publication the research is classified `CLASS C (TRANSFORM ONLY)` /
`NOT_ELIGIBLE`. No DDR/controller, XPU, SMMU, SCM, EL2, EL3, or protected-memory
write has been performed, and no alias or protection bypass has been observed.

**In scope:** defects in what is published here — an analyzer or decoder that can
be made to accept unsafe input, a tool whose device-facing path lacks a sound
rollback, a private identifier that reached the published tree, or a claim
carrying a stronger evidence label than its artifacts support.

**Out of scope:** vulnerabilities in Qualcomm or Samsung firmware, in TrustZone,
QHEE, XBL, or in Android itself. Report those to the relevant vendor, not here.
Requests for help attacking a device you do not own are also out of scope and
will not be answered.

## Reporting

Please do **not** open a public issue first for a security-sensitive finding.

Use GitHub's private vulnerability reporting for this repository
(Security → Report a vulnerability). If that is unavailable, open an issue that
states only that you have a security report and requests a private channel —
without the details.

A useful report includes:

- the affected component, file, or manifest;
- reproduction conditions;
- whether physical ownership or control of a device is required to trigger it;
- the impact you believe it has.

## If this research ever reaches a bypass

It has not. This policy is stated in advance so that the answer does not depend
on the circumstances at the time.

If work in this repository establishes that a Normal World physical address can
be admitted by one protection layer and then transformed to a different protected
DRAM destination — that is, a real isolation bypass rather than the present
`UNKNOWN` — it will go to the affected vendors through coordinated disclosure
**before** any public write-up, and the public tree will carry the structural
finding without a reproduction path until that process concludes.

Nothing in this repository is to be published in a form that functions as a
working attack against a device the reader does not own.

## Expectations

This is a personal research project maintained by one person, so please expect
best-effort rather than guaranteed response times. Reports that turn out to be
real will be fixed in the public tree and credited in the commit unless you ask
otherwise.

## Evidence labels

Findings here are labelled `PROVED`, `SUPPORTED`, `HYPOTHESIS`, `UNKNOWN`, or
`REFUTED`. A label that overstates its artifacts is a reportable defect in the
same way a code bug is: the discipline is the product, and a claim that drifts
above its evidence damages it more than a missing feature would.
