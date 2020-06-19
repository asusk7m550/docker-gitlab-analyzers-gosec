# Gosec analyzer changelog

## v2.8.0
- Update Docker image to use golang 1.14 (!46)

## v2.7.1
 - Change GoSec external configuration reading from os.env to cli flag (!43)

## v2.7.0
 - Update logging to use commonutil (!42)

## v2.6.2
- Drop securego base docker image in favor of packaging gosec binary (!39)

## v2.6.1
- Remove `location.dependency` from the generated SAST report (!41)

## v2.6.0
- Add support for specifying a `gosec` configuration file with `SAST_GOSEC_CONFIG` (!19 @firelizzard)

## v2.5.1
- Use Alpine as builder image (!33)

## v2.5.0
- Change location where custom CA certs are written (!30)

## v2.4.0
- Add `id` field to vulnerabilities in JSON report (!31)

## v2.3.0
- Add support for custom CA certs (!28)

## v2.2.1
- Use gosec v2.2.0
- Use CWE mappings introduced in gosec v2.2.0
- Change `compareKey` from `<file>:<code>:G-<gosec-rule-id>` to `<file>:<lineno>:<code>:CWE-<cweid>`

## v2.2.0
- Build Docker image on top of securego/gosec:v2.1.0 (!21 @bartjkdp)

## v2.1.1
- Add rule URLs for G101, G102, G103, G104, G107, G201, & G202

## v2.1.0
- Build Docker image on top of securego/gosec:2.0.0 (!16 @bartjkdp)

## v2.0.1
- Update common to v2.1.6

## v2.0.0
- Switch to new report syntax with `version` field

## v1.5.0 (unreleased)
- Build Docker image on top of securego/gosec:1.2.0

## v1.4.0
- Add `Scanner` property and deprecate `Tool`

## v1.3.0
- Rename this analyzer to gosec from Go AST Scanner (https://gitlab.com/gitlab-org/gitlab-ee/issues/6999)

## v1.2.0
- Show command error output

## v1.1.0
- Enrich report with more data

## v1.0.0
- Rewrite using Go and analyzers common library

## v0.1.0
- initial release
