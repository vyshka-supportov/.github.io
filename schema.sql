CREATE TABLE IF NOT EXISTS whitelist_users (
  discord_id VARCHAR(20) PRIMARY KEY,
  username TEXT,
  global_name TEXT,
  avatar_url TEXT,
  role TEXT NOT NULL CHECK (role IN ('Администратор','Куратор','Мастер','Саппорт')),
  added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS oauth_sessions (
  sid VARCHAR NOT NULL COLLATE "default" PRIMARY KEY,
  sess JSON NOT NULL,
  expire TIMESTAMP(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_sessions_expire_idx ON oauth_sessions (expire);
