# Rate Limit & Isolation

*Source: https://api-docs.deepseek.com/quick_start/rate_limit*

## Concurrency Limits by Model

DeepSeek enforces account-level concurrency restrictions:

| Model | Concurrent Connections |
|-------|----------------------|
| `deepseek-v4-pro` | 500 |
| `deepseek-v4-flash` | 2,500 |
| `deepseek-v4-flash-vision-exp` | 2,500 |

A request counts as one concurrent connection from the time it is sent until the model response is complete. When limits are exceeded, users receive HTTP 429 error responses.

## user_id Isolation Feature

The `user_id` parameter enables three key functions:

1. **Content Safety Isolation** - distinguishes user identities for safety protocols
2. **KVCache Isolation** - separates cache data for privacy protection
3. **Scheduling Isolation** - manages per-user request queuing

For accounts with expanded quotas, each `user_id` receives its own concurrency ceiling matching the model's base limits. Empty IDs are treated as a distinct `user_id` category.

### Implementation Requirements

The parameter must be a string matching the pattern `[a-zA-Z0-9\-_]+` (maximum 512 characters). User personally identifiable information should not be included.

### OpenAI SDK syntax

Place the parameter within the `extra_body` dictionary rather than as a direct argument:

```python
response = client.chat.completions.create(
    model="deepseek-v4-flash",
    messages=[...],
    extra_body={"user_id": "user123"}
)
```

### Anthropic SDK syntax

Include it under the `metadata` dictionary with a maximum token parameter also specified:

```python
response = client.messages.create(
    model="deepseek-v4-flash",
    max_tokens=1024,
    messages=[...],
    metadata={"user_id": "user123"}
)
```

## Keep-Alive Mechanism

During response delays, connections remain open with periodic keep-alive signals (empty lines for non-streaming, SSE comments for streaming). If the request has not started inference after 10 minutes, the server will close the connection.
