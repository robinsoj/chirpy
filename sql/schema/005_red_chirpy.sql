-- +goose Up
alter TABLE users add column is_chirpy_red boolean not null default false;

-- +goose Down
alter TABLE users delete column is_chirpy_red;