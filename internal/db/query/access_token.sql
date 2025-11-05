-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    user_id, refresh_token, expired_at
) VALUES (
             $1, $2, $3
         ) RETURNING *;

-- name: UpsertRefreshToken :one
INSERT INTO refresh_tokens (user_id, refresh_token, expired_at)
VALUES ($1, $2, $3)
    ON CONFLICT (user_id)
DO UPDATE SET
    refresh_token = EXCLUDED.refresh_token,
           expired_at = EXCLUDED.expired_at,
           created_at = NOW()
RETURNING *;