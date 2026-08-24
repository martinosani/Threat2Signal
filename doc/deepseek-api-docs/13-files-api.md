# Files API

*Source: https://api-docs.deepseek.com/guides/files_api*

## Overview

DeepSeek's Files API enables uploading and reusing images across multiple requests without re-uploading. The service supports JPEG, PNG, GIF, and WebP formats and allows files up to 64 MiB.

## Key Operations

### Upload

Files are submitted via multipart form-data to `POST /files` with required `file` and `purpose` ("user_data") fields. Optional expiration settings range from 1 hour to 30 days.

### Management

Users can:
- **List files** with pagination parameters (`after`, `limit`, `order`, `purpose`)
- **Retrieve** individual file information
- **Delete** files via dedicated endpoints

### Usage

Uploaded files are referenced in chat requests using a `file_id` within a `file` content block, compatible with the `deepseek-v4-flash-vision-exp` model.

## Limits

| Limit | Value |
|-------|-------|
| Maximum single file | 64 MiB |
| Storage per user | 25 GiB |
| Maximum stored files | 10,000 |
| Upload completion deadline | 10 minutes |

## API Variants

### OpenAI-Compatible

Standard OpenAI file upload format with multipart form-data.

### Anthropic-Compatible

Requires the header `anthropic-beta: files-api-2025-04-14` and uses different parameter names:
- `size_bytes` instead of `bytes`
- RFC 3339 timestamps instead of Unix seconds

## File-Referenced Images

File-referenced images bypass the 32 MiB per-image inline limit, supporting up to 64 MiB per file in requests.
