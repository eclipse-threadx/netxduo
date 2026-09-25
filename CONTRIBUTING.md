# Contributing to Eclipse ThreadX NetX Duo

Thanks for your interest in this project.

## Project description

NetX Duo is the Eclipse ThreadX dual IPv4 and IPv6 TCP/IP stack for deeply embedded real-time and IoT applications. This repository contains the core stack, protocol and connectivity add-ons, NetX Secure, cryptography libraries, and time-sensitive networking support. NetX Duo uses ThreadX; some file-server add-ons also use FileX.

Eclipse ThreadX provides a vendor-neutral, open source, safety-certified OS for real-time applications, published under a permissive license. The Eclipse ThreadX suite encompasses:

* **ThreadX** - advanced real-time operating system (RTOS) designed specifically for deeply embedded applications
* **NetX Duo** - advanced, industrial-grade TCP/IP network stack designed specifically for deeply embedded real-time and IoT applications
* **FileX** - high-performance, FAT-compatible file system that is fully integrated with the ThreadX kernel
* **GUIX** - complete, embedded graphical user interface (GUI) library
* **GUIX Studio** - design environment, facilitating the creation and maintenance of all graphical elements for GUIX
* **USBX** - high-performance USB host, device, and on-the-go (OTG) embedded stack, fully integrated with the ThreadX kernel
* **LevelX** - flash wear levelling for FileX and stand-alone purposes
* **TraceX** - analysis tool that provides a graphical view of real-time system events to better understand the behaviour of real-time systems
* **ZoneX** - deterministic partitioning hypervisor for mixed-criticality embedded systems
* **SampleX** - samples and demos for the components above

Project websites:

* https://threadx.io
* https://projects.eclipse.org/projects/iot.threadx

This file describes how to contribute to **NetX Duo**. General contribution conventions are shared across the Eclipse ThreadX repositories; build and test instructions differ by component.

## Terms of Use

This repository is subject to the Terms of Use of the Eclipse Foundation: https://www.eclipse.org/legal/termsofuse.php

## New contributors

Welcome. Here is the shortest path from zero to a merged pull request.

1. **Create an Eclipse Foundation account.** https://accounts.eclipse.org/user/register

   The email address on that account matters: it must be the same address you use as the `Author` of your Git commits. If the two do not match, the ECA check on your pull request will fail.

2. **Sign the Eclipse Contributor Agreement (ECA).** See the section below. This is a one-time step and covers every Eclipse Foundation project.

   <br>

3. **Configure Git accordingly.**

   ```
   git config user.name "Your Name"
   git config user.email "the-address-on-your-eclipse-account@example.org"
   ```

4. **Pick something to work on.** Open issues are fair game, including ones nobody has assigned. Please leave a comment on the issue saying you intend to work on it, so two people do not solve the same problem twice. If an issue carries a `good first issue` label, it is a reasonable starting point.

5. **Have an idea for a new feature? Discuss it first.** Open a thread in [GitHub Discussions](https://github.com/orgs/eclipse-threadx/discussions) or raise it on the [developer mailing list](https://accounts.eclipse.org/mailing-list/threadx-dev) before writing code. Network protocol and public API changes can affect many applications, so discuss the shape of a feature before submitting a finished implementation.

Bug fixes and documentation corrections need no prior discussion. Send them straight in.

## Eclipse Development Process

This Eclipse Foundation open project is governed by the Eclipse Foundation Development Process and operates under the terms of the Eclipse IP Policy.

* https://eclipse.org/projects/dev_process
* https://www.eclipse.org/org/documents/Eclipse_IP_Policy.pdf

## Eclipse Contributor Agreement

In order to be able to contribute to Eclipse Foundation projects you must electronically sign the Eclipse Contributor Agreement (ECA): https://www.eclipse.org/legal/ECA.php

The ECA provides the Eclipse Foundation with a permanent record that you agree that each of your contributions will comply with the commitments documented in the Developer Certificate of Origin (DCO). Having an ECA on file associated with the email address matching the "Author" field of your contribution's Git commits fulfills the DCO's requirement that you sign-off on your contributions.

For more information, please see the Eclipse Committer Handbook: https://www.eclipse.org/projects/handbook/#resources-commit

## Required tooling

Build and test NetX Duo with CMake and Ninja. The root CMake project requires CMake 3.13 or later. The Linux regression workers run on Ubuntu 24.04 with GCC 14 and `gcovr` 8.6. `scripts/install.sh` installs their host tools. The Windows simulator has `win32` and `win64` MSVC ports; its builds use the Visual Studio Build Tools, without requiring the Visual Studio IDE. The CI regression suites described below run on Linux.

NetX Duo depends on ThreadX. Some file-server add-ons also use FileX. Initialize the repository's submodules before building or testing:

```sh
git submodule update --init --recursive
```

NetX Duo code must be C99-compatible. The core CMake regression project compiles its C sources with `-std=c99`.

## Building and testing

The regression suites live under `test/cmake/`. For each suite, run its build script before its test script. The wrapper scripts accept `all` or one or more named build profiles; with no profile, they use `all`. For example:

```sh
scripts/build_nxd.sh default_build_coverage
scripts/test_nxd.sh default_build_coverage
```

| Scripts | What they cover |
| ------- | --------------- |
| `build_nxd.sh`, `test_nxd.sh` | Core NetX Duo, IPv4 and IPv6 options, and protocol add-ons. |
| `build_nxd64.sh`, `test_nxd64.sh` | 64-bit host configuration. |
| `build_nxd_fast.sh`, `test_nxd_fast.sh` | Fast-path configuration. |
| `build_web.sh`, `test_web.sh` | Web protocols. |
| `build_ptp.sh`, `test_ptp.sh` | Precision Time Protocol. |
| `build_mqtt.sh`, `test_mqtt.sh` | MQTT. |
| `build_secure.sh`, `test_secure.sh` | NetX Secure. |
| `build_crypto.sh`, `test_crypto.sh` | Cryptography library. |
| `build_mqtt_interoperability.sh`, `test_mqtt_interoperability.sh` | MQTT interoperability. |
| `build_secure_interoperability.sh`, `test_secure_interoperability.sh` | TLS interoperability. |

All scripts in the table are under `scripts/`. The interoperability suites need their matching `scripts/install_mqtt.sh` or `scripts/install_secure.sh` setup. The Azure IoT add-on has separate `scripts/build_azure_iot.sh` and `scripts/test_azure_iot.sh` wrappers. Use `scripts/check_endian.sh` for changes that might depend on little-endian compilation.

The Windows simulator provides PowerShell build and test script pairs for the core, 64-bit host, fast-path, Web, PTP, MQTT, Secure, and crypto suites. Run them from PowerShell with the Visual Studio Build Tools available. Supply the ThreadX and FileX source checkouts explicitly when the build script accepts them. For example:

```powershell
scripts/build_nxd.ps1 -Arch win64 -Configuration default_build_coverage -ThreadXDir 'path/to/threadx' -FilexDir 'path/to/filex'
scripts/test_nxd.ps1 -Arch win64 -Configuration default_build_coverage
```

Use `-Arch win32` for the 32-bit simulator. The Windows test scripts run CTest serially because concurrent simulator tests can interfere with timing. The interoperability and Azure IoT scripts listed above are Linux scripts; there are no matching Windows PowerShell runners.

On Linux, a profile ending in `_coverage` produces a coverage report for that configuration. The MSVC Windows runs do not collect coverage. The `dev` workflow uploads reports from selected coverage profiles, but it does not enforce a 100% coverage floor. The project goal remains 100% test coverage. Add or update regression tests for new behaviour, and describe which profiles and targets actually exercised the change. A successful host build does not establish that code runs correctly on an embedded target.

## Continuous integration

Two GitHub Actions workflows run different branch policies:

| Workflow | When it runs | What it checks |
| -------- | ------------ | -------------- |
| `ci-dev.yml` | Pull requests and pushes to `dev`, plus manual runs. | Always runs the core `default_build_coverage` smoke profile. A change classifier selects further NetX Duo, Web, PTP, MQTT, 64-bit, fast-path, Secure, crypto, and interoperability profiles. A final gate requires every selected job to pass. |
| `regression_test.yml` | Pull requests and pushes to `master`, plus manual runs. | Runs the broad regression suites through the ThreadX reusable regression workflow. |

`ci-dev.yml` uses `_test-suite.yml` as its reusable Linux worker. The classifier is tested on every run; if it cannot classify a change, the workflow selects the full suite and the gate reports the classifier failure. An unselected job is not evidence that its tests ran. Read the job summary to see which profiles were selected, and run any additional suites needed for your change.

## Pull request acceptance criteria

**Pull requests must target the `dev` branch.** `master` holds the latest release; see [Release model and support](#release-model-and-support) below. A pull request opened against `master` will be asked to retarget.

Before requesting a review, check your contribution against this list.

**Process**

* The branch is a feature branch based on `dev`. Never commit directly to `master` or `dev`.
* Your ECA is signed and the commit `Author` email matches your Eclipse account.
* The pull request is one logical change. Unrelated fixes belong in separate pull requests.
* Commit subject lines start with a past-tense verb, for example `Fixed the memory allocator`.
* The pull request explains what changed and why, and how you verified it.

**Code**

* The code is C99-compatible.
* It follows the coding style of the surrounding code.
* New functions and structures are documented in comments, as in existing code.
* MISRA C rules are followed as closely as practical, taking MISRA C 2004, 2012 and 2023 into account. Any deviation is explicit, names the rule being circumvented, and justifies it in a comment.
* `goto` is not used.
* Do not add new external dependencies. This is a hard rule. ThreadX, FileX, and the existing test tools and submodules are already part of the build and test setup described above.
* When implementing an industry standard, code is not copied from an existing implementation. Existing implementations may inform your work, but you must identify those sources clearly.
* Code is written with the suite's priorities in mind: runtime speed and small code size.
* New C and assembly files, and edited C and assembly files, carry the appropriate header and attribution (see below).

**Verification**

* All applicable CI checks are green.
* The change builds without new warnings on the reference toolchains.
* Regression tests covering the change are added or updated. The project targets 100% test coverage; a pull request that lowers coverage needs a stated reason. State which profiles ran and any relevant coverage gap.
* API or behaviour changes come with a matching documentation pull request against [rtos-docs-asciidoc](https://github.com/eclipse-threadx/rtos-docs-asciidoc).

**Security**

If you discover a security issue while working on a change, do not describe it in a public pull request. Follow [SECURITY.md](SECURITY.md) instead.

## AI-assisted contributions

**AI-assisted contributions are welcome**, provided they are attributed.

Two things are non-negotiable:

1. **Attribution.** Mark AI-assisted C and assembly files as described below, and identify the tool and model in the commit message.
2. **Human responsibility.** The human contributor submitting the pull request is responsible for the contribution - technically and legally. Signing the ECA means *you* certify the contribution's provenance. An AI tool cannot sign the ECA and cannot hold that responsibility. Review what the tool produced, understand it, and verify that it is correct and that you have the right to contribute it. "The model wrote it" is not a defence.

This is consistent with the Eclipse Foundation's [Generative AI Usage Guidelines](https://www.eclipse.org/projects/guidelines/genai/) and the [Eclipse Project Handbook](https://www.eclipse.org/projects/handbook/#genai). Please read them before submitting AI-assisted work.

### Using a coding agent

Give a coding agent this contribution guide and the build instructions for the area it changes. Review its output against the same acceptance criteria as any other contribution. In particular, check C99 compatibility, surrounding style, test coverage, and the right protocol suite or target for runtime verification.

### Header for new files

Add this header when creating a new C or assembly (`.S`) file:

```c
/***************************************************************************
 * Copyright (c) <current_year> Eclipse ThreadX contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * AI Disclosure: This file was largely AI-generated by <product> (<model_and_version>).
 * The AI-generated portions may be considered public domain (CC0-1.0)
 * and not subject to the project's licence. The human contributor has
 * reviewed and verified that the code is correct.
 *
 * SPDX-License-Identifier: MIT and CC0-1.0
 **************************************************************************/
```

Substitute the current year, product name, and model and version. If a file was written without generative AI, omit the AI Disclosure paragraph and use `SPDX-License-Identifier: MIT`.

### Header for existing files

When editing an existing C or assembly file whose copyright is from 2025 or earlier, and which does not already mention Eclipse ThreadX contributors, add this line to the header:

```c
 * Copyright (c) <current_year> Eclipse ThreadX contributors
```

It goes *below* the older copyright. All copyright lines must stay in chronological order. For example:

```c
/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2026 Eclipse ThreadX contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/
```

If the edit was AI-assisted and the file does not already carry an AI disclosure line, add this line just under the header:

```c
// Portions of this file were generated with AI assistance.
```

Use the comment marker already used by the file. Keep an existing disclosure line unchanged and never add a second one. If you copy an existing file to get started on a new one, treat the result as a new file: use the new-file header, do not carry the old one over.

### Commit attribution

Add an `Assisted-by` trailer to each commit that contains AI-assisted changes:

```text
Fixed the packet receive status

A packet could report an out-of-date status after a receive operation.

The receive path now returns the status set by the completed operation.

The affected NetX Duo regression profile passed all tests.

Assisted-by: <product> (<model_and_version>) <email>
```

Use the product's accepted name (`Claude Code`, `Copilot`, `Codex`, or `Gemini`) and the model string reported by the tool. Do not use `Co-Authored-By` for AI attribution. Commit subjects and pull request titles start with a past-tense verb and stay within 72 characters. The message body states the cause, fix, and test result in that order; wrap commit bodies at 88 characters. Pull request descriptions use one line per paragraph.

## Release model and support

This section summarises the project's [Release Model and Support Policy](https://github.com/eclipse-threadx/rtos-docs-asciidoc/blob/main/rtos-docs/home/modules/ROOT/pages/releases-and-support.adoc), which is the authoritative version.

### Version numbers

Eclipse ThreadX releases generally follow [Semantic Versioning](https://semver.org/). Given a version number **X.Y.Z.Bh**, for example `6.5.0.202601a`:

* **X** increases for a *milestone release*. Components currently stay at version 6.
* **Y** increases for a *feature release* adding a major feature.
* **Z** increases for a *maintenance release* of minor fixes and improvements.
* **B** is a *build number* identifying the quarter of publication - `202601` is Q1 2026.
* **h** denotes a *hotfix release*, identified by a letter. Hotfix releases are component-specific.

### Release cadence

The project adopted a predictable quarterly release model in September 2025 and has published a release every quarter since.

Quarterly releases ship new versions of every component, whether or not that component saw code changes, so that version numbers do not drift apart between components. A release shipping no code changes for a component says so in its release notes.

Urgent fixes between quarterly releases ship as *hotfix* releases. Those contain only security fixes, or fixes for serious problems that prevent building or testing applications.

### Branches

The project runs a time-based release train on trunk-based development. There are no long-term support branches and no backports to older releases.

* `master` always contains the latest quarterly or hotfix release.
* `dev` is the integration branch. Pull requests are merged there during the quarter. Track `dev` if you want to test new features and fixes ahead of a release.
* A quarterly release is performed by merging `dev` into `master`.

### Support policy

Issues in the codebase are fixed on a best-effort basis, and pull requests fixing existing or new issues are gladly accepted.

Security vulnerabilities disclosed confidentially are handled under the [Eclipse Foundation's security policy](https://www.eclipse.org/security/policy/). Once a candidate vulnerability is confirmed, the team works to deliver a fix as soon as possible, shipping it in the next quarterly release or as a hotfix depending on timing. Resolved vulnerabilities are disclosed immediately after a release containing the fix becomes available. The team aims to resolve newly confirmed vulnerabilities within three months; that period may be extended by the Project Leadership Chain together with the Eclipse Foundation Security team where appropriate.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

### Roadmap

The project team plans its work on a [public GitHub project board](https://github.com/orgs/eclipse-threadx/projects/2/views/2).

### A note on older releases

Microsoft contributed only the Azure RTOS codebase v6.x to the Eclipse Foundation. Older ThreadX releases (v5.x and lower) sold by Express Logic were never made open source, and Microsoft has discontinued sales and support for them. Users of ThreadX 5.x and lower should upgrade to the latest release of Eclipse ThreadX as soon as possible.

## Documentation

The documentation is published at **https://threadx.io**. PDF manuals for every component, in A4 and US Letter formats, are attached as assets to each GitHub release.

### The stack

Documentation is written in [AsciiDoc](https://asciidoc.org/) and built with [Antora](https://antora.org/). PDF manuals are produced by the [Antora Assembler](https://docs.antora.org/assembler/latest/) with `asciidoctor-pdf`.

### The workflow

1. The single source of truth is [rtos-docs-asciidoc](https://github.com/eclipse-threadx/rtos-docs-asciidoc). All documentation changes are made there, as pull requests, following the same branch rules as the code repositories.
2. At release time the site is generated from that source into [rtos-docs-html](https://github.com/eclipse-threadx/rtos-docs-html), which holds the rendered HTML and exists solely for website integration. Do not edit it by hand - your changes will be overwritten by the next build.
3. The website then serves the generated content from `rtos-docs-html`.

The older `rtos-docs` repository, which held the documentation in Markdown, is archived and superseded by `rtos-docs-asciidoc`. Do not send changes there.

If your contribution adds or changes an API or a feature, open a matching pull request against `rtos-docs-asciidoc`.

## Developer resources

Information regarding source code management, builds, coding standards, and more: https://projects.eclipse.org/projects/iot.threadx/developer

The project maintains the following repositories:

**Components**

* https://github.com/eclipse-threadx/threadx
* https://github.com/eclipse-threadx/netxduo
* https://github.com/eclipse-threadx/filex
* https://github.com/eclipse-threadx/guix
* https://github.com/eclipse-threadx/usbx
* https://github.com/eclipse-threadx/levelx
* https://github.com/eclipse-threadx/tracex
* https://github.com/eclipse-threadx/zonex

**Samples and platforms**

* https://github.com/eclipse-threadx/samplex
* https://github.com/eclipse-threadx/supported-platforms

**Documentation**

* https://github.com/eclipse-threadx/rtos-docs-asciidoc
* https://github.com/eclipse-threadx/rtos-docs-html

**Community and process**

* https://github.com/eclipse-threadx/discussions
* https://github.com/eclipse-threadx/trustedx
* https://github.com/eclipse-threadx/.github

## Contact

### GitHub Discussions

https://github.com/orgs/eclipse-threadx/discussions

Q&A, feedback, and announcements. Decisions taken by the project team are documented here as well. This is usually the fastest way to reach both the team and other users.

### Main ThreadX mailing list

https://accounts.eclipse.org/mailing-list/threadx

News and updates about the ThreadX project and the ThreadX Alliance.

### Developer mailing list

https://accounts.eclipse.org/mailing-list/threadx-dev

Project team conversations. Feel free to jump in and ask non-technical questions there.

### User mailing list

https://accounts.eclipse.org/mailing-list/threadx-users

Ask your technical questions and discuss issues here.
