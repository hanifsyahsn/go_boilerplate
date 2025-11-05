CREATE TABLE "refresh_tokens" (
                                 "id" bigserial PRIMARY KEY,
                                 "user_id" bigint NOT NULL,
                                 "refresh_token" varchar NOT NULL,
                                 "expired_at" timestamptz NOT NULL,
                                 "created_at" timestamptz NOT NULL DEFAULT (now()),
                                 "updated_at" timestamptz NOT NULL DEFAULT (now())
);

ALTER TABLE "refresh_tokens" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_unique UNIQUE (user_id);

CREATE INDEX idx_refresh_tokens_refresh_token ON refresh_tokens (refresh_token);