BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "users" (
	"id"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"email"	TEXT NOT NULL UNIQUE,
	"created"	DATETIME NOT NULL DEFAULT (strftime('%s','now')),
	"password"	TEXT NOT NULL,
	"verification_code"	TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
	"email_verified"	DATETIME DEFAULT NULL
);
CREATE TABLE IF NOT EXISTS "domains" (
	"id"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"host"	TEXT NOT NULL,
	"account"	INTEGER NOT NULL,
	"key"	TEXT NOT NULL DEFAULT (lower(hex(randomblob(8)))) UNIQUE,
	"created"	DATETIME NOT NULL DEFAULT (strftime('%s','now'))
);
COMMIT;
