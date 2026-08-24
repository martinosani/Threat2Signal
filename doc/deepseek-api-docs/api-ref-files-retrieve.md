# API Reference: Retrieve File

*Source: https://api-docs.deepseek.com/api/retrieve-file*

## Endpoint

**GET** `/files/:file_id`

Returns information about a specific file.

## Request

### Path Parameter

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_id` | string | Yes | The identifier for the file to retrieve |

## Response (HTTP 200)

```json
{
  "id": "file-api-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "object": "file",
  "bytes": 102400,
  "created_at": 1700000000,
  "filename": "image.jpg",
  "purpose": "user_data"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | File identifier in format `file-api-...` |
| `object` | string | Always `"file"` |
| `bytes` | integer | File size in bytes |
| `created_at` | integer | Unix timestamp (seconds) of creation |
| `filename` | string | The file's name |
| `purpose` | string | Purpose value: `user_data` |
| `expires_at` | integer | Unix timestamp when file expires (optional) |
