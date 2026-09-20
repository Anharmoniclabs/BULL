CREATE TABLE IF NOT EXISTS checkpoints (
  session TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  head TEXT NOT NULL,
  previous_hash TEXT,
  frame TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(session, sequence)
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_session_seq
ON checkpoints(session, sequence DESC);
