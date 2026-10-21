"""Local append-only JSONL hash chain.

This is the Community storage backend. It has no update and no delete.
WORM enforcement for the retention period is a Pro backend (S3 Object Lock
or an append-only database). The file should still be treated as write-once
by the operator (for example a directory the service account can only append
to). Hashes make silent edits detectable.
"""

from __future__ import annotations

import errno
import fcntl
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from ..anchor import assess, read_head, write_head
from ..canonical import GENESIS, canonicalize, seal
from ..chain import VerifyReport, verify_bytes
from ..errors import AuditStoreError, ChainIntegrityError
from ..records import SYSTEM_PRINCIPAL, build_event, format_timestamp, utc_now
from ..signers.unsigned import UnsignedSigner


_LOG = logging.getLogger("mcp_glp_audit_proxy.technical")


def jsonl_store(settings: Any, signer: Any, options: dict[str, Any] | None = None) -> JsonlAuditStore:
    """Entry point factory. Pro stores use (settings, signer, options=).

    Community ignores ``options``. The mapping is plugins.storage.options.
    """
    del options
    return JsonlAuditStore(
        settings.audit_path,
        signer=signer,
        checkpoint_every=settings.checkpoint_every,
        legal_hold=settings.retention.legal_hold,
    )


class JsonlAuditStore:
    def __init__(
        self,
        path: Path,
        *,
        signer: Any | None = None,
        checkpoint_every: int = 100,
        legal_hold: bool = False,
        now: Any | None = None,
    ) -> None:
        self.path = Path(path)
        self.signer = signer or UnsignedSigner()
        self.checkpoint_every = checkpoint_every
        self.legal_hold = legal_hold
        self._now = now or utc_now

    def health(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return False
        os.close(fd)
        return True

    def read_entries(self) -> list[dict[str, Any]]:
        report = self._locked_report()
        if not report.ok:
            raise ChainIntegrityError("; ".join(report.errors))
        return report.entries

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        sealed, _checkpoint = self._append(event, allow_checkpoint=True)
        return sealed

    def refuse_disposal(self) -> None:
        """Disposal is not a Community operation. Legal hold refuses it explicitly."""
        if self.legal_hold:
            raise AuditStoreError("legal hold: disposal refused")
        raise AuditStoreError(
            "append-only JSONL store: disposal is not implemented "
            "(retention-period WORM enforcement is a Pro backend)"
        )

    def _locked_report(self) -> Any:
        if not self.path.exists():
            return _apply_anchor(self.path, VerifyReport(ok=True, head_hash=GENESIS))
        try:
            fd = os.open(self.path, os.O_RDONLY)
        except OSError as exc:
            raise _write_failure(exc) from exc
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH)
                report = verify_bytes(_read_all(fd))
                if report.ok:
                    report = _apply_anchor(self.path, report)
            except OSError as exc:
                raise _write_failure(exc) from exc
        finally:
            _quiet_unlock(fd)
        return report

    def _append(self, event: dict[str, Any], *, allow_checkpoint: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
        if not self.health():
            raise AuditStoreError("audit store unavailable")
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise _write_failure(exc) from exc
        checkpoint: dict[str, Any] | None = None
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                report = verify_bytes(_read_all(fd))
                if not report.ok:
                    raise ChainIntegrityError("; ".join(report.errors))
                self._require_anchor(report)
                sealed = _seal_next(event, report.entries)
                os.lseek(fd, 0, os.SEEK_END)
                _write_all(fd, canonicalize(sealed) + b"\n")
                os.fsync(fd)
                written = report.entries + [sealed]
                if not self._try_head(sealed):
                    return sealed, None
                if allow_checkpoint and _needs_checkpoint(written, self.checkpoint_every):
                    checkpoint = self._checkpoint_event(sealed)
                    checkpoint_sealed = _seal_next(checkpoint, written)
                    os.lseek(fd, 0, os.SEEK_END)
                    _write_all(fd, canonicalize(checkpoint_sealed) + b"\n")
                    os.fsync(fd)
                    self._try_head(checkpoint_sealed)
                    checkpoint = checkpoint_sealed
                return sealed, checkpoint
            except AuditStoreError:
                raise
            except OSError as exc:
                # open, write and fsync failures must surface as store errors so
                # the proxy latches fail-closed instead of retrying the call.
                raise _write_failure(exc) from exc
        finally:
            _quiet_unlock(fd)

    def _require_anchor(self, report: VerifyReport) -> None:
        status = assess(report, read_head(self.path))
        if not status.ok:
            raise AuditStoreError(status.errors[0])
        if status.lag != 1:
            return
        last = report.entries[-1]
        try:
            write_head(self.path, int(last["seq"]), str(last["entry_hash"]))
        except OSError as exc:
            raise _write_failure(exc) from exc
        _LOG.info("audit head advanced over a one-record lag to seq=%s", last["seq"])

    def _try_head(self, entry: dict[str, Any]) -> bool:
        try:
            write_head(self.path, int(entry["seq"]), str(entry["entry_hash"]))
        except OSError as exc:
            _LOG.warning(
                "audit head lags by 1 after write failure seq=%s errno=%s",
                entry.get("seq"),
                exc.errno,
            )
            return False
        return True

    def _checkpoint_event(self, head: dict[str, Any]) -> dict[str, Any]:
        moment = self._now()
        if not isinstance(moment, datetime):
            moment = utc_now()
        stamped = format_timestamp(moment)
        payload = canonicalize(
            {"head_hash": head["entry_hash"], "seq": head["seq"], "timestamp": stamped}
        )
        signature = self.signer.sign(payload)
        return build_event(
            method="audit/checkpoint",
            record_class="technical",
            status="ok",
            server="proxy",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "mcp-glp-audit-proxy", "name": "mcp-glp-audit-proxy", "version": None, "model_id": None},
            protocol_version=None,
            session_id=None,
            arguments={"head_hash": head["entry_hash"], "seq": head["seq"]},
            result={"signature": signature},
            policy_action="allow",
            policy_rule="checkpoint",
            reason=_checkpoint_reason(self.signer),
            timestamp=stamped,
        )


def _checkpoint_reason(signer: Any) -> str:
    """Name the signer that produced this checkpoint.

    The unsigned sentence is used only for the Community unsigned signer.
    """
    name = getattr(signer, "name", None)
    if not isinstance(name, str) or not name or name == "unsigned":
        return "unsigned checkpoint (Community); signing is a Pro plugin"
    return f"checkpoint signed by {name}"


def _needs_checkpoint(entries: list[dict[str, Any]], every: int) -> bool:
    if every <= 0 or not entries:
        return False
    if entries[-1].get("method") == "audit/checkpoint":
        return False
    count = 0
    for entry in reversed(entries):
        if entry.get("method") == "audit/checkpoint":
            break
        count += 1
    return count >= every


def _seal_next(event: dict[str, Any], prior: list[dict[str, Any]]) -> dict[str, Any]:
    body = dict(event)
    body.pop("entry_hash", None)
    body.pop("prev_hash", None)
    body.pop("seq", None)
    body["seq"] = 1 if not prior else int(prior[-1]["seq"]) + 1
    prev = GENESIS if not prior else str(prior[-1]["entry_hash"])
    return seal(body, prev)


def _read_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        block = os.read(fd, 1024 * 64)
        if not block:
            break
        chunks.append(block)
    return b"".join(chunks)


def _write_all(fd: int, data: bytes) -> None:
    view = data
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write on audit store")
        view = view[written:]


def _apply_anchor(path: Path, report: VerifyReport) -> VerifyReport:
    try:
        head = read_head(path)
    except AuditStoreError as exc:
        return VerifyReport(
            ok=False,
            entries=report.entries,
            errors=[str(exc)],
            head_hash=report.head_hash,
        )
    status = assess(report, head)
    if not status.ok:
        return VerifyReport(
            ok=False,
            entries=report.entries,
            errors=status.errors,
            head_hash=report.head_hash,
        )
    report.anchor_lag = status.lag
    return report


def _write_failure(exc: OSError) -> AuditStoreError:
    detail = exc.strerror or exc.__class__.__name__
    code = exc.errno
    return AuditStoreError(f"audit store write failed: errno={code} {detail}")


def _quiet_unlock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass
