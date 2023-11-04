schema.db: schema.sql
	rm schema.db || true
	sqlite3 schema.db < schema.sql