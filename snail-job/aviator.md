# snail-job aviator expression injection (≤ v1.9.0)

**Product**: snail-job

**Affected Versions**: ≤ v1.9.0

**address**: https://github.com/aizuda/snail-job

## Vulnerability Description

In snail-job versions 1.9.0 and below, the `/snail-job/workflow/check-node-expression` interface does not validate user input and executes it directly as an aviator expression, resulting in remote code execution.

## POC

