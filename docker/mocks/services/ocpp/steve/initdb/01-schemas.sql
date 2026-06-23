-- SPDX-License-Identifier: GPL-3.0-or-later
-- OIDA SteVe stack: per-config database schemas.
--
-- The MariaDB image creates `stevedb` (MYSQL_DATABASE) + the `steve` user for
-- us. We add two MORE schemas so each SteVe configuration owns an isolated
-- database, because SteVe persists registered-chargebox state and we want the
-- "open" vs "registered-only" vs "secure" configs not to share that state.
--
-- SteVe runs Flyway/jOOQ migrations against whichever schema it is pointed at
-- on first boot, so these only need to exist (empty) - SteVe creates tables.

CREATE DATABASE IF NOT EXISTS stevedb_open
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS stevedb_registered
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS stevedb_secure
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

GRANT ALL PRIVILEGES ON stevedb_open.*       TO 'steve'@'%';
GRANT ALL PRIVILEGES ON stevedb_registered.* TO 'steve'@'%';
GRANT ALL PRIVILEGES ON stevedb_secure.*     TO 'steve'@'%';
FLUSH PRIVILEGES;
