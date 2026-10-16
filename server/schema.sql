-- CloudUp accounts and sync (API v1). MariaDB 10.11, InnoDB, utf8mb4.
-- Idempotent: every statement can run again on a live database.
-- Apply with: sudo -n mysql cloudup < schema.sql   (server/deploy.sh does this)

-- One row per account. Emails are stored lower-cased (ASCII only) by the API,
-- so the unique key is case-folded. Binary values are raw bytes, not base64.
CREATE TABLE IF NOT EXISTS users (
  id                          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email                       VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  salt                        VARBINARY(16)  NOT NULL,
  kdf                         VARCHAR(255)   NOT NULL,   -- JSON: {"alg":"argon2id","m":..,"t":..,"p":..}
  auth_hash                   VARCHAR(255)   NOT NULL,   -- password_hash(auth_key, PASSWORD_ARGON2ID)
  wrapped_vault_key           VARBINARY(255) NOT NULL,
  recovery_wrapped_vault_key  VARBINARY(255) NOT NULL,
  recovery_hash               VARCHAR(255)   NOT NULL,   -- password_hash(recovery_auth, PASSWORD_ARGON2ID)
  verified_at                 DATETIME       NULL,       -- NULL until the emailed code is entered
  created_at                  DATETIME       NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  KEY ix_users_unverified (verified_at, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Emailed 6-digit codes. One live code per user and purpose; only an HMAC of
-- the code is stored. attempts counts every guess; the code dies at 5.
CREATE TABLE IF NOT EXISTS codes (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id     BIGINT UNSIGNED NOT NULL,
  purpose     ENUM('verify','reset') NOT NULL,
  code_hash   BINARY(32)      NOT NULL,
  expires_at  DATETIME        NOT NULL,
  attempts    TINYINT UNSIGNED NOT NULL DEFAULT 0,
  created_at  DATETIME        NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_codes_user_purpose (user_id, purpose),
  KEY ix_codes_expires (expires_at),
  CONSTRAINT fk_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Signed-in devices. token_hash = SHA-256 of the bearer token.
CREATE TABLE IF NOT EXISTS sessions (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id       BIGINT UNSIGNED NOT NULL,
  token_hash    BINARY(32)      NOT NULL,
  device_name   VARCHAR(100)    NOT NULL,
  created_at    DATETIME        NOT NULL,
  last_seen_at  DATETIME        NOT NULL,
  expires_at    DATETIME        NOT NULL,   -- last_seen_at + 90 days
  PRIMARY KEY (id),
  UNIQUE KEY uq_sessions_token (token_hash),
  KEY ix_sessions_user (user_id),
  KEY ix_sessions_expires (expires_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The encrypted vault. No row means version 0 (nothing uploaded yet).
CREATE TABLE IF NOT EXISTS vaults (
  user_id     BIGINT UNSIGNED NOT NULL,
  version     BIGINT UNSIGNED NOT NULL,
  `blob`      MEDIUMBLOB      NOT NULL,     -- decoded bytes, at most 1.5 MiB (2 MiB of base64)
  updated_at  DATETIME        NOT NULL,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_vaults_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Short-lived tokens from recover/start, single use. token_hash = SHA-256.
CREATE TABLE IF NOT EXISTS reset_tokens (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id     BIGINT UNSIGNED NOT NULL,
  token_hash  BINARY(32)      NOT NULL,
  expires_at  DATETIME        NOT NULL,
  created_at  DATETIME        NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_reset_tokens_token (token_hash),
  KEY ix_reset_tokens_user (user_id),
  CONSTRAINT fk_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sliding-window rate limit log. bucket = "<action>:<ip|email>:<HMAC of the
-- value>", so neither IPs nor emails are stored here in the clear.
CREATE TABLE IF NOT EXISTS rate_limits (
  id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  bucket  VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  at      INT UNSIGNED NOT NULL,              -- unix time
  PRIMARY KEY (id),
  KEY ix_rate_limits_bucket_at (bucket, at),
  KEY ix_rate_limits_at (at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
