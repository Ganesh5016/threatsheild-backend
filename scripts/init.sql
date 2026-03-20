-- THREATSHIELD — Initial database setup
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;   -- for text search on scan results

-- Indexes created automatically by SQLAlchemy models
-- This file is for any extra DB setup needed at first run
