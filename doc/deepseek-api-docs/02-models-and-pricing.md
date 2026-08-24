# Models & Pricing

*Source: https://api-docs.deepseek.com/quick_start/pricing*

## Overview

DeepSeek offers three primary models with tiered pricing based on token usage. The prices listed below are in units of per 1M tokens.

## Available Models

**DeepSeek-V4-Flash**: A faster, more affordable option with a 1M context window and 384K maximum output tokens.

**DeepSeek-V4-Pro**: A premium model designed for complex tasks, also featuring 1M context and 384K output capacity.

**DeepSeek-V4-Flash-Vision-Exp**: An experimental vision-capable variant of the Flash model.

## Pricing Structure

Pricing varies between peak and off-peak hours. Peak hours are 01:00 - 04:00 and 06:00 - 10:00 UTC, Monday through Friday (all other hours are off-peak). Off-peak rates are fifty percent of peak rates.

### Peak Pricing (per 1M tokens)

| Category | DeepSeek-V4-Flash | DeepSeek-V4-Pro |
|----------|-------------------|-----------------|
| Input (Cache Hit) | $0.007 | $0.014 |
| Input (Cache Miss) | $0.22 | $1.32 |
| Output | $0.66 | $3.96 |

### Off-Peak Pricing (per 1M tokens)

Off-peak rates are 50% of peak rates.

## Key Features

All models support JSON output, tool calls, and the Responses API. The Flash and Pro versions enable thinking mode by default, while vision features are limited to the experimental model.

| Feature | V4-Flash | V4-Pro | V4-Flash-Vision-Exp |
|---------|----------|--------|---------------------|
| JSON Output | Yes | Yes | Yes |
| Tool Calls | Yes | Yes | Yes |
| Responses API | Yes | Yes | Yes |
| Thinking Mode | Yes (default) | Yes (default) | Yes (default) |
| Vision | No | No | Yes |
| Context Window | 1M | 1M | 1M |
| Max Output Tokens | 384K | 384K | 384K |
