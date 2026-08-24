# Context Caching is Available (2024/08/02)

*Source: https://api-docs.deepseek.com/news/news0802*

## Overview

DeepSeek introduced disk-based context caching technology that dramatically reduces API costs by caching repetitive content. The service charges $0.014 per million tokens for cache hits, representing a cost reduction of up to 90% compared to standard pricing.

## Key Benefits

### Cost Savings
Users achieve significant savings through cached token processing. Historical data shows that users save over 50% on average even without optimization efforts.

### Latency Reduction
For a 128K prompt with high reference content, first token latency decreased from 13 seconds to approximately 500 milliseconds.

## How It Works

The caching system automatically operates without requiring code changes. It identifies identical input prefixes and retrieves cached content rather than reprocessing. Only requests with matching prefixes from the beginning trigger cache hits; partial matches elsewhere in inputs do not activate the cache.

## Common Use Cases

- Question-and-answer assistants
- Role-playing scenarios
- Document analysis tasks
- Code repository references
- Few-shot learning implementations

## Monitoring

The API response includes two metrics for tracking cache performance:
- `prompt_cache_hit_tokens` -- tokens served from cache
- `prompt_cache_miss_tokens` -- tokens requiring full processing

## Security

Each user's cache remains isolated and logically separated from other users, ensuring privacy and data security.
