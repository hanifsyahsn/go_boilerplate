CREATE TABLE "users" (
                         "id" bigserial PRIMARY KEY,
                         "name" varchar NOT NULL,
                         "email" varchar NOT NULL,
                         "password" varchar NOT NULL,
                         "created_at" timestamptz NOT NULL DEFAULT (now()),
                         "updated_at" timestamptz NOT NULL DEFAULT (now())
);

ALTER TABLE users
    ADD CONSTRAINT users_email_unique UNIQUE (email);