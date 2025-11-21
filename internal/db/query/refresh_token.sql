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
           expired_at = EXCLUDED.expired_at
RETURNING *;

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens
WHERE refresh_token = $1;

-- name: GetRefreshTokenByUserId :one
SELECT * FROM refresh_tokens
WHERE refresh_token = $1 and user_id = $2
LIMIT 1;