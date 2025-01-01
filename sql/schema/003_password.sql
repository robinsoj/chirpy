-- +goose Up
alter TABLE users add column hashed_password text not null default 'unset';

-- +goose Down
alter TABLE users delete column hashed_password;