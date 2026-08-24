# Token & Token Usage

*Source: https://api-docs.deepseek.com/quick_start/token_usage*

## Overview

Tokens are the basic units used by models to represent natural language text, and also the units used for billing.

## Conversion Ratios

Approximate token-to-character conversion rates:

- **English text**: approximately 0.3 tokens per character
- **Chinese text**: approximately 0.6 tokens per character

However, these are estimates only, as different tokenization methods used by different models can produce varying results. The actual token count from API responses serves as the definitive measurement.

## Practical Tools

### Offline Token Calculator

Users can download a tokenizer package to compute token usage locally without making API calls.

### Image Token Estimation

The documentation includes a calculator for estimating tokens consumed by images based on dimensions, though the actual number of tokens produced during processing may vary slightly.

## Key Takeaway

Users should rely on the API's returned usage data as the authoritative source rather than manual calculations, since tokenization varies across different models.
