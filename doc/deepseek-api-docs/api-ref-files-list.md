# API Reference: List Files

*Source: https://api-docs.deepseek.com/api/list-files*

## Endpoint

**GET** `/files`

Retrieves all files belonging to a user with cursor-based pagination support.

## Request Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `after` | string | - | A file_id cursor for pagination, returning files listed after the specified one |
| `limit` | integer | 1000 | Number of files to return (1-1000) |
| `order` | string | "asc" | Sort order by creation time: "asc" or "desc" |
| `purpose` | string | - | Filter by file purpose; only "user_data" is currently supported |

## Response (HTTP 200)

```json
{
  "object": "list",
  "data": [
    {
      "id": "file-api-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      "object": "file",
      "bytes": 102400,
      "created_at": 1700000000,
      "filename": "image.jpg",
      "purpose": "user_data"
    }
  ],
  "first_id": "file-api-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "last_id": "file-api-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "has_more": false
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `object` | string | Always `"list"` |
| `data` | array | Array of file objects |
| `first_id` | string | ID of first file in list |
| `last_id` | string | ID of last file in list |
| `has_more` | boolean | Whether additional files exist |

### File Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | File identifier (format: `file-api-...`) |
| `object` | string | Always `"file"` |
| `bytes` | integer | File size in bytes |
| `created_at` | integer | Unix timestamp of creation |
| `filename` | string | Name of the file |
| `purpose` | string | File purpose (`user_data`) |
| `expires_at` | integer | Optional expiration timestamp |
