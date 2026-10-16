PRAGMA page_size=4096;
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=EXTRA;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=0;
PRAGMA trusted_schema=OFF;
PRAGMA max_page_count=8192;
BEGIN IMMEDIATE;
CREATE TABLE enrollment (
    id INTEGER PRIMARY KEY CHECK(id=1),
    profile TEXT NOT NULL CHECK(profile='ptlc-nom-anchor-sqlite-comparison-v1'),
    capacity INTEGER NOT NULL CHECK(capacity BETWEEN 1 AND 16),
    initial BLOB NOT NULL CHECK(length(initial) BETWEEN 1 AND 2097152)
) STRICT;
CREATE TABLE anchor_state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 16),
    phase TEXT NOT NULL CHECK(phase IN ('ACTIVE','RETIRED')),
    complete BLOB NOT NULL CHECK(length(complete) BETWEEN 1 AND 2097152)
) STRICT;
CREATE TABLE requests (
    position INTEGER PRIMARY KEY CHECK(position BETWEEN 1 AND 16),
    request_id TEXT NOT NULL UNIQUE CHECK(length(request_id)=64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    nonce TEXT NOT NULL UNIQUE CHECK(length(nonce)=64 AND nonce NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK(kind IN ('ADVANCE','RETIRE')),
    complete_before BLOB NOT NULL CHECK(length(complete_before) BETWEEN 1 AND 2097152),
    exact_request BLOB NOT NULL CHECK(length(exact_request) BETWEEN 1 AND 4194304),
    complete_after BLOB NOT NULL CHECK(length(complete_after) BETWEEN 1 AND 2097152)
) STRICT;
CREATE TRIGGER validate_expected_state BEFORE INSERT ON requests BEGIN
    SELECT CASE WHEN (SELECT count(*) FROM enrollment)!=1 OR (SELECT count(*) FROM anchor_state)!=1
        THEN RAISE(ABORT,'missing exact enrollment') END;
    SELECT CASE WHEN (SELECT phase FROM anchor_state WHERE id=1)!='ACTIVE'
        THEN RAISE(ABORT,'terminal enrollment') END;
    SELECT CASE WHEN NEW.position!=(SELECT revision+1 FROM anchor_state WHERE id=1)
        OR NEW.complete_before IS NOT (SELECT complete FROM anchor_state WHERE id=1)
        THEN RAISE(ABORT,'exact expected state refused') END;
    SELECT CASE WHEN NEW.position>(SELECT capacity FROM enrollment WHERE id=1)
        THEN RAISE(ABORT,'finite capacity refused') END;
END;
CREATE TRIGGER retain_result AFTER INSERT ON requests BEGIN
    UPDATE anchor_state SET revision=NEW.position,
        phase=CASE WHEN NEW.kind='RETIRE' THEN 'RETIRED' ELSE 'ACTIVE' END,
        complete=NEW.complete_after WHERE id=1;
END;
CREATE TRIGGER no_request_update BEFORE UPDATE ON requests BEGIN
    SELECT RAISE(ABORT,'retained request is immutable');
END;
CREATE TRIGGER no_request_delete BEFORE DELETE ON requests BEGIN
    SELECT RAISE(ABORT,'retained request cannot be trimmed');
END;
CREATE TRIGGER no_enrollment_update BEFORE UPDATE ON enrollment BEGIN
    SELECT RAISE(ABORT,'enrollment cannot be reset');
END;
CREATE TRIGGER no_enrollment_delete BEFORE DELETE ON enrollment BEGIN
    SELECT RAISE(ABORT,'enrollment cannot be removed');
END;
COMMIT;
