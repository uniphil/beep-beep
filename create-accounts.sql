BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "domains" (
	"host"	TEXT NOT NULL,
	"user_id"	INTEGER NOT NULL,
	"key"	TEXT NOT NULL DEFAULT (lower(hex(randomblob(8)))),
	"created"	DATETIME NOT NULL DEFAULT (strftime('%s','now')),
	PRIMARY KEY("host","user_id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "users" (
	"id"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"email"	TEXT NOT NULL UNIQUE,
	"created"	DATETIME NOT NULL DEFAULT (strftime('%s','now')),
	"password"	TEXT NOT NULL,
	"verification_code"	TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
	"email_verified"	DATETIME DEFAULT NULL
);
COMMIT;
