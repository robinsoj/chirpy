-- name: LookUpRefresh :one
select *
from refresh_tokens
where token = $1 and revoked_at is null;

-- name: RevokeToken :exec
update refresh_tokens
set revoked_at = now(), updated_at = now()
where token = $1;

-- name: StoreRefreshToken :exec
insert into refresh_tokens (token, created_at, updated_at, user_id, expires_at) values (
	$1,
	now(),
	now(),
	$2,
	$3
);