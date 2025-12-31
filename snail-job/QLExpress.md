# Snail-job QLExpress expression injection (≤ v1.9.0)

**Product**: snail-job

**Affected Versions**: ≤ v1.9.0

**address**: https://github.com/aizuda/snail-job

## Vulnerability Description

In snail-job versions 1.9.0 and below, the `/snail-job/workflow/check-node-expression` interface does not validate user input and executes it directly as an QLExpress expression, resulting in remote code execution.

## POC

```java
new org.springframework.expression.spel.standard.SpelExpressionParser().parseExpression("T(java.lang.Runtime).getRuntime().exec('calc')").getValue();
```
<img width="1873" height="844" alt="image" src="https://github.com/user-attachments/assets/1930d2d5-2a70-4693-a1a1-89ce02244651" />

## Code
The vulnerable code interface is located at `com.aizuda.snailjob.server.web.controller.WorkflowController`
<img width="1358" height="228" alt="image" src="https://github.com/user-attachments/assets/3aa387a6-6f9e-49b5-b7c4-cf47361c4821" />

After a series of initializations, the `expressionEngine.eval` method is called.
<img width="1462" height="492" alt="image" src="https://github.com/user-attachments/assets/16aad6dc-f9d5-4382-8510-f6739e0db50e" />

Following the `eval` method, it was found that the `doEval` method was called. Further investigation led to the implementation class `QLExpressEngine`.
<img width="1292" height="493" alt="image" src="https://github.com/user-attachments/assets/7bdd3df0-e6ae-440f-91d7-7f165f0465e2" />

The `QLExpressEngine` class overrides the `doEval` method, and the parameter `expression` is controllable. The developer directly put the expression parameter into the execute method, resulting in QLExpress expression injection.
<img width="1331" height="462" alt="image" src="https://github.com/user-attachments/assets/d50d2d55-3b5f-4dcb-990c-edaa96f3d8dd" />
