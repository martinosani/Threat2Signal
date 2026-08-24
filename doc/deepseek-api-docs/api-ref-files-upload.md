# API Reference: Upload File

*Source: https://api-docs.deepseek.com/api/create-file*

## Endpoint

**POST** `/files`

Upload image files (JPEG, PNG, GIF, WebP) for later reference via `file_id` in chat requests.

## Request

Content-Type: `multipart/form-data`

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file` | binary | Yes | The image to upload (max 64 MiB) |
| `purpose` | string | Yes | Must be `"user_data"` |
| `expires_after[anchor]` | string | No | Must be `"created_at"` if provided |
| `expires_after[seconds]` | integer | No | Between 3600-2592000 seconds (1 hour to 30 days) |

Both expiration fields are required together; omit both to retain files permanently.

Format detection occurs automatically from file content.

## Response (HTTP 200)

```json
{
  "id": "file-api-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "object": "file",
  "bytes": 102400,
  "created_at": 1700000000,
  "filename": "image.jpg",
  "purpose": "user_data",
  "expires_at": 1700086400
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Identifier in format `file-api-...` |
| `object` | string | Always `"file"` |
| `bytes` | integer | File size in bytes |
| `created_at` | integer | Unix timestamp of creation |
| `filename` | string | Original filename |
| `purpose` | string | `"user_data"` |
| `expires_at` | integer | Optional expiration timestamp |
