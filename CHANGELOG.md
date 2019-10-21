# Gosec analyzer changelog

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
