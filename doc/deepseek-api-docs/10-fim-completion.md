# FIM Completion (Beta)

*Source: https://api-docs.deepseek.com/guides/fim_completion*

## Overview

DeepSeek's FIM (Fill In the Middle) completion feature allows developers to provide a prefix and a suffix (optional), and the model will complete the content in between. This capability serves practical applications like content and code completion.

## Key Constraints

1. Maximum token output is capped at 4K
2. Implementation requires setting `base_url=https://api.deepseek.com/beta` to access the beta feature

## Code Implementation Example

```python
from openai import OpenAI

client = OpenAI(
    api_key="<your-api-key>",
    base_url="https://api.deepseek.com/beta",
)

response = client.completions.create(
    model="deepseek-v4-pro",
    prompt="def fib(a):",
    suffix="    return fib(a-1) + fib(a-2)",
    max_tokens=128,
)

print(response.choices[0].text)
```

## Integration with VSCode

DeepSeek supports integration with Continue, a VSCode plugin for code completion. Users can reference the project's GitHub documentation to configure this integration for enhanced development workflows.
