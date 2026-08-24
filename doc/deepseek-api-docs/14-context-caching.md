# Context Caching

*Source: https://api-docs.deepseek.com/guides/kv_cache*

## Overview

DeepSeek's Context Caching feature operates automatically on a disk-based system, storing frequently used input prefixes to accelerate subsequent requests. Each cached prefix is an independent, complete unit.

## How Cache Hits Work

The system persists cache units at three key points:

1. **Request boundaries** -- at the end of user input and model output
2. **Common prefix detection** -- when multiple requests share initial content
3. **Fixed token intervals** -- for lengthy inputs to ensure some caching occurs

### Example

If a first request contains content A+B, a second request with A+B+C will successfully reuse the cached A+B portion. However, a request with A+C won't match, though the system will then cache just A for future reuse.

## Monitoring Cache Performance

Response objects include two usage metrics:

```json
{
  "usage": {
    "prompt_cache_hit_tokens": 1024,
    "prompt_cache_miss_tokens": 512
  }
}
```

- `prompt_cache_hit_tokens` -- cached input tokens
- `prompt_cache_miss_tokens` -- non-cached tokens

## Important Limitations

- The hard disk cache only matches the prefix part of the user's input. The output is still generated through computation.
- Results remain non-deterministic based on temperature settings despite cache hits.
- The system operates on a best-effort basis without guaranteeing full cache effectiveness.
- Unused caches automatically expire within hours to days.

## Common Use Cases

- Question-and-answer assistants
- Role-playing scenarios
- Document analysis tasks
- Code repository references
- Few-shot learning implementations

## Security

Each user's cache remains isolated and logically separated from other users, ensuring privacy and data security.
