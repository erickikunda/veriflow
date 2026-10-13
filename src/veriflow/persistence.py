"""Local SQLAlchemy persistence with explicit migrations and transaction control."""

import sqlite3
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import JSON, BigInteger, ForeignKey, String, UniqueConstraint, create_engine, event
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from veriflow.domain import VeriFlowError


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    owner: Mapped[str] = mapped_column(String(200))
    classification: Mapped[str] = mapped_column(String(100))


class ImportBatch(Base):
    __tablename__ = "imports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(200), unique=True)
    request_sha256: Mapped[str] = mapped_column(String(64))
    input_root: Mapped[str] = mapped_column(String(4096))
    created_at: Mapped[str] = mapped_column(String(40))


class ImportControl(Base):
    __tablename__ = "import_controls"
    __table_args__ = (UniqueConstraint("import_id", "request_key"),)
    import_id: Mapped[str] = mapped_column(ForeignKey("imports.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(primary_key=True)
    state: Mapped[str] = mapped_column(String(20))
    request_key: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[str] = mapped_column(String(40))


class Snapshot(Base):
    __tablename__ = "snapshots"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    manifest: Mapped[dict] = mapped_column(JSON)


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    repo_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    state: Mapped[str] = mapped_column(String(30))
    profile: Mapped[str] = mapped_column(String(30))
    snapshot_id: Mapped[str | None] = mapped_column(ForeignKey("snapshots.id"))
    created_at: Mapped[str] = mapped_column(String(40))


class ImportItem(Base):
    __tablename__ = "import_items"
    __table_args__ = (UniqueConstraint("import_id", "row_number"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    import_id: Mapped[str] = mapped_column(ForeignKey("imports.id"), index=True)
    row_number: Mapped[int]
    state: Mapped[str] = mapped_column(String(30), index=True)
    spec: Mapped[dict | None] = mapped_column(JSON)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"))
    error: Mapped[str | None] = mapped_column(String(2000))
    attempts: Mapped[int] = mapped_column(default=0)


class SourceIndex(Base):
    __tablename__ = "source_indexes"
    __table_args__ = (UniqueConstraint("snapshot_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("snapshots.id"))
    version: Mapped[str] = mapped_column(String(100))
    state: Mapped[str] = mapped_column(String(30))
    report: Mapped[dict | None] = mapped_column(JSON)


class IndexedFile(Base):
    __tablename__ = "indexed_files"
    __table_args__ = (UniqueConstraint("index_id", "path"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    index_id: Mapped[str] = mapped_column(ForeignKey("source_indexes.id"), index=True)
    path: Mapped[str] = mapped_column(String(512))
    result: Mapped[dict] = mapped_column(JSON)


class CodeqlAttempt(Base):
    __tablename__ = "codeql_attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    result: Mapped[dict] = mapped_column(JSON)


class ScanAttempt(Base):
    __tablename__ = "scan_attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    report: Mapped[dict] = mapped_column(JSON)


class Candidate(Base):
    __tablename__ = "candidates"
    __table_args__ = (UniqueConstraint("attempt_id", "fingerprint"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("scan_attempts.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[dict] = mapped_column(JSON)


class EvidenceBundle(Base):
    __tablename__ = "evidence_bundles"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("candidates.id"), index=True)
    content: Mapped[dict] = mapped_column(JSON)


class TriageBudget(Base):
    __tablename__ = "triage_budgets"
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), primary_key=True)
    limit_micro_usd: Mapped[int] = mapped_column(BigInteger)
    max_requests: Mapped[int] = mapped_column(default=100, server_default="100")


class TriageCall(Base):
    __tablename__ = "triage_calls"
    __table_args__ = (UniqueConstraint("run_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    bundle_id: Mapped[str] = mapped_column(ForeignKey("evidence_bundles.id"))
    request_key: Mapped[str] = mapped_column(String(200))
    request_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    state: Mapped[str] = mapped_column(String(40))
    charged_micro_usd: Mapped[int] = mapped_column(BigInteger)
    result: Mapped[dict] = mapped_column(JSON)


class DiscoveryCall(Base):
    __tablename__ = "discovery_calls"
    __table_args__ = (UniqueConstraint("run_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("scan_attempts.id"), index=True)
    request_key: Mapped[str] = mapped_column(String(200))
    request_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    state: Mapped[str] = mapped_column(String(40))
    charged_micro_usd: Mapped[int] = mapped_column(BigInteger)
    result: Mapped[dict] = mapped_column(JSON)


class PublishedReport(Base):
    __tablename__ = "published_reports"
    __table_args__ = (
        UniqueConstraint("run_id", "version"),
        UniqueConstraint("run_id", "input_digest"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    version: Mapped[int]
    input_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    content: Mapped[dict] = mapped_column(JSON)


class OperatorReview(Base):
    __tablename__ = "operator_reviews"
    __table_args__ = (
        UniqueConstraint("candidate_id", "revision"),
        UniqueConstraint("candidate_id", "request_key"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("candidates.id"), index=True)
    bundle_id: Mapped[str] = mapped_column(ForeignKey("evidence_bundles.id"))
    revision: Mapped[int]
    request_key: Mapped[str] = mapped_column(String(200))
    request_sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[dict] = mapped_column(JSON)


class RuleDraft(Base):
    __tablename__ = "rule_drafts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("candidates.id"), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    state: Mapped[str] = mapped_column(String(30))
    content: Mapped[dict] = mapped_column(JSON)


class RuleRegistry(Base):
    __tablename__ = "rule_registries"
    __table_args__ = (UniqueConstraint("version"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int]
    created_at: Mapped[str] = mapped_column(String(40))
    content: Mapped[dict] = mapped_column(JSON)


class RuleApproval(Base):
    __tablename__ = "rule_approvals"
    __table_args__ = (
        UniqueConstraint("draft_id"),
        UniqueConstraint("request_key"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    draft_id: Mapped[str] = mapped_column(ForeignKey("rule_drafts.id"), index=True)
    registry_id: Mapped[str] = mapped_column(ForeignKey("rule_registries.id"))
    request_key: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[str] = mapped_column(String(40))
    content: Mapped[dict] = mapped_column(JSON)


class ProfileDraft(Base):
    __tablename__ = "profile_drafts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40))
    state: Mapped[str] = mapped_column(String(30))
    content: Mapped[dict] = mapped_column(JSON)


class ProfileApproval(Base):
    __tablename__ = "profile_approvals"
    __table_args__ = (UniqueConstraint("request_key"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    draft_id: Mapped[str] = mapped_column(ForeignKey("profile_drafts.id"), index=True)
    registry_id: Mapped[str] = mapped_column(ForeignKey("rule_registries.id"))
    request_key: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[str] = mapped_column(String(40))
    content: Mapped[dict] = mapped_column(JSON)


class ProfileTest(Base):
    __tablename__ = "profile_tests"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    draft_id: Mapped[str] = mapped_column(ForeignKey("profile_drafts.id"), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    passed: Mapped[bool]
    content: Mapped[dict] = mapped_column(JSON)


class BenchmarkScorecard(Base):
    __tablename__ = "benchmark_scorecards"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(String(100), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    content: Mapped[dict] = mapped_column(JSON)


class Store:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.database = self.root / "veriflow.db"
        self.engine = create_engine(URL.create("sqlite", database=str(self.database)))

        @event.listens_for(self.engine, "connect")
        def configure(connection: sqlite3.Connection, _record):
            # SQLAlchemy owns BEGIN so DDL/reads participate in transactions too.
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")

        @event.listens_for(self.engine, "begin")
        def begin(connection):
            connection.exec_driver_sql("BEGIN")

        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
        config = Config()
        config.set_main_option("script_location", str(files("veriflow") / "migrations"))
        with self.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")

    def require_initialized(self) -> None:
        if not self.database.is_file():
            raise VeriFlowError("State is not initialized; run veriflow init first")

    @contextmanager
    def transaction(self):
        self.require_initialized()
        with self.sessions.begin() as session:
            yield session

    def close(self) -> None:
        self.engine.dispose()


@contextmanager
def exclusive_worker(root: Path):
    """One local worker; the OS releases ownership if the process dies.

    This is deliberately not a distributed lease or the production scheduler.
    """
    import fcntl

    with (root / "worker.lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise VeriFlowError("A local worker already owns this state directory") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
