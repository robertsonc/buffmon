"""Explicit allowlist for the POST operations buffmon may send to Orchestrator.

buffmon's Orchestrator client is read-only. Some reads are only offered as POST
(a query in the body); each one buffmon uses must be a rule in the POST policy
file (``deploy/orchestrator/post-allowlist.yaml``), which is reviewed like code.

What a rule does:

* names one exact path (no placeholders) and gives it an id; a mapping refers
  to the id, never to a raw path;
* lists every query parameter and top-level body key the request may carry,
  with its type and limits; anything else is refused before sending;
* records why it is safe: ``effect: read`` (the only accepted value), purpose,
  approver, approval date, the releases it was verified on, and the spec
  operation it corresponds to.

What a rule cannot do: declare a write. ``effect`` accepts only ``read``. That
is the approver's assertion, which code cannot verify, so it is backed by a
tripwire (:func:`tripwire`): write-sounding or secret-sounding words in the
operation, or a missing read verb, must each be acknowledged in
``reviewed_terms``. A change to Orchestrator (acknowledge, clear, configure, ...)
belongs in a separate, interactively confirmed tool with its own audit, never in
the monitoring path.

The policy fails closed: no file, no POSTs. The poller narrows it to the rules
its mapping uses, and the client checks every POST against its rule twice:
before sending, and in the httpx request hook on the bytes actually sent.
"""

from __future__ import annotations

import hashlib
import re
import stat
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")

# -- Tripwire ---------------------------------------------------------------------
# A rule's path, spec operationId and spec summary are scanned for words that
# suggest the call is not a plain read. Every flag must be listed under the
# rule's `reviewed_terms`, which is how a reviewer records "I read the operation
# and it only reads". This is a tripwire, not a classifier: words cannot prove
# a call is read-only. The approval (effect: read, approved_by, verified_on) is
# the control; the tripwire makes the approver look twice where it matters.
#
# Tuned against the 419 POST operations of the Orchestrator 10.0 export: every
# operation it leaves unflagged is a statistics, state or inventory read.
WRITE_TERMS = (
    "acknowledge", "ack", "activate", "add", "apply", "approve", "assign", "attach", "cancel", "capture",
    "change", "clear", "clearance", "clone", "comment", "commit", "configure", "consolidate", "consume",
    "create", "deactivate", "decrement", "delete", "deletion", "deny", "deploy", "detach", "disable",
    "discover", "edit", "enable", "execute", "generate", "grant", "import", "increment", "init", "initialize",
    "install", "kill", "lock", "login", "logout", "mark", "merge", "migrate", "modify", "move", "mute",
    "note", "pause", "ping", "post", "provision", "purge", "push", "put", "reboot", "reclassify",
    "reclassification", "register", "release", "remove", "rename", "renew", "replace", "reserve", "reset",
    "restart", "restore", "resume", "revoke", "rollback", "rotate", "run", "save", "schedule", "send", "set",
    "shutdown", "start", "stop", "store", "submit", "subscribe", "suppress", "sync", "synchronize", "test",
    "traceroute", "trigger", "update", "upgrade", "upload", "write",
)
# Words that suggest the response carries secrets (IPsec PSKs, cloud-security
# API keys, certificates): reads, but not ones a monitoring key should make casually.
SENSITIVE_TERMS = (
    "auth", "certificate", "config", "credential", "key", "passphrase", "password", "private", "psk",
    "secret", "token",
)
READ_VERBS = (
    "count", "describe", "export", "fetch", "find", "get", "list", "lookup", "query", "read", "retrieve",
    "search", "show", "view",
)
NO_READ_VERB = "no-read-verb"
_INFLECTIONS = ("", "s", "es", "d", "ed", "ing", "ment", "ments")
_NEGATING_PREFIXES = ("un", "re", "de", "dis")


def _words(text: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.findall(r"[a-z]+", spaced.lower())


def _is_write_word(term: str, word: str) -> bool:
    candidates = [word] + [word[len(p):] for p in _NEGATING_PREFIXES if word.startswith(p) and len(word) > len(p) + 2]
    for w in candidates:
        if any(w == term + suffix for suffix in _INFLECTIONS):
            return True
        if len(term) >= 5 and w.startswith(term):
            return True
    return False


def _is_sensitive_word(term: str, word: str) -> bool:
    return term in word if len(term) >= 4 else word in (term, term + "s")


def tripwire(path: str, operation_id: str | None, summary: str) -> list[str]:
    """Flags for a POST operation: write-sounding words, words that suggest
    secrets in the response, and ``no-read-verb`` when neither the operationId
    nor the summary starts with a read verb (get, retrieve, list, ...)."""
    words = set(_words(" ".join((path, operation_id or "", summary))))
    flags = {t for t in WRITE_TERMS if any(_is_write_word(t, w) for w in words)}
    flags |= {t for t in SENSITIVE_TERMS if any(_is_sensitive_word(t, w) for w in words)}
    leading = [(_words(x) or [""])[0] for x in (operation_id or "", summary)]
    if not any(w in READ_VERBS for w in leading):
        flags.add(NO_READ_VERB)
    return sorted(flags)


class PostPolicyError(ValueError):
    pass


ValueType = Literal["string", "int", "bool", "list_of_string", "list_of_int"]


class ValueRule(BaseModel):
    """Constraints on one query parameter or one top-level body key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: ValueType = "string"
    enum: list[str] | None = None
    min: int | None = None
    max: int | None = None
    pattern: str | None = None          # applied to strings and to each list item
    max_items: int | None = Field(default=None, ge=1)
    required: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"pattern {self.pattern!r} is not a valid regex: {exc}") from exc
        if self.max_items is not None and not self.type.startswith("list_"):
            raise ValueError("max_items only applies to list types")
        if (self.min is not None or self.max is not None) and self.type not in ("int", "list_of_int"):
            raise ValueError("min/max only apply to int types")
        return self

    def check(self, name: str, value: Any) -> str | None:
        """Returns why ``value`` is not allowed, or None."""
        if self.type in ("list_of_string", "list_of_int"):
            if not isinstance(value, list):
                return f"{name} must be a list"
            if self.max_items is not None and len(value) > self.max_items:
                return f"{name} has {len(value)} items (max {self.max_items})"
            for i, item in enumerate(value):
                why = self._scalar(f"{name}[{i}]", item, "string" if self.type == "list_of_string" else "int")
                if why:
                    return why
            return None
        return self._scalar(name, value, self.type)

    def _scalar(self, name: str, value: Any, kind: str) -> str | None:
        if kind == "bool":
            return None if isinstance(value, bool) or str(value).lower() in ("true", "false") else \
                f"{name} must be a boolean"
        if kind == "int":
            try:
                n = int(str(value)) if not isinstance(value, bool) else None
            except ValueError:
                n = None
            if n is None:
                return f"{name} must be an integer"
            if self.min is not None and n < self.min:
                return f"{name}={n} is below {self.min}"
            if self.max is not None and n > self.max:
                return f"{name}={n} is above {self.max}"
            return None
        if not isinstance(value, str):
            return f"{name} must be a string"
        if self.enum is not None and value not in self.enum:
            return f"{name}={value!r} is not one of {self.enum}"
        if self.pattern is not None and not re.fullmatch(self.pattern, value):
            return f"{name}={value!r} does not match {self.pattern}"
        return None


class SpecRef(BaseModel):
    """The operation in the vendor's API description this rule corresponds to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str | None = None
    summary: str = Field(min_length=1)


class PostRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    method: Literal["POST"] = "POST"
    path: str
    # The only accepted value: buffmon never sends a POST that changes state.
    effect: Literal["read"]
    purpose: str = Field(min_length=10)
    spec: SpecRef
    verified_on: list[str] = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    approved_on: date
    params: dict[str, ValueRule] = {}
    body: dict[str, ValueRule] = {}
    max_body_bytes: int = Field(default=65536, ge=2, le=4 * 1024 * 1024)
    # Tripwire flags (see tripwire()) a reviewer has looked at and accepts for
    # this operation. Must equal the flags exactly: an unreviewed flag or a stale
    # entry both fail validation.
    reviewed_terms: list[str] = []

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not RULE_ID.match(v):
            raise ValueError(f"rule id {v!r}: 3-64 chars of [a-z0-9-], starting and ending alphanumeric")
        return v

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not v.startswith("/") or "{" in v or "?" in v or "#" in v or "//" in v or ".." in v:
            raise ValueError(f"path {v!r} must be an exact path: '/'-rooted, no placeholders, query or '..'")
        return v

    @model_validator(mode="after")
    def _reviewed(self) -> Self:
        flags = set(tripwire(self.path, self.spec.operation_id, self.spec.summary))
        unreviewed = sorted(flags - set(self.reviewed_terms))
        stale = sorted(set(self.reviewed_terms) - flags)
        if unreviewed:
            raise ValueError(
                f"rule {self.id}: {self.path} / {self.spec.operation_id or '-'} / {self.spec.summary!r} trips "
                f"{unreviewed}. Read the operation in the API reference; only if it does nothing but read, "
                f"list these under reviewed_terms."
            )
        if stale:
            raise ValueError(f"rule {self.id}: reviewed_terms {stale} are not flagged for this operation; remove them")
        return self

    def check_request(self, params: Mapping[str, Any], body: Any) -> list[str]:
        """Every reason the request does not fit this rule (empty: it fits)."""
        problems: list[str] = []
        for k, v in params.items():
            rule = self.params.get(k)
            if rule is None:
                problems.append(f"query parameter {k!r} is not allowed by rule {self.id}")
            elif (why := rule.check(k, v)) is not None:
                problems.append(why)
        problems += [f"query parameter {k!r} is required by rule {self.id}"
                     for k, r in self.params.items() if r.required and k not in params]
        if not isinstance(body, dict):
            problems.append(f"rule {self.id} needs a JSON object body")
            return problems
        for k, v in body.items():
            rule = self.body.get(k)
            if rule is None:
                problems.append(f"body key {k!r} is not allowed by rule {self.id}")
            elif (why := rule.check(k, v)) is not None:
                problems.append(why)
        problems += [f"body key {k!r} is required by rule {self.id}"
                     for k, r in self.body.items() if r.required and k not in body]
        return problems


class PostPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    rules: list[PostRule] = []
    # Filled by load_policy: sha256 of the file, logged at startup for audit.
    sha256: str = ""

    @model_validator(mode="after")
    def _unique(self) -> Self:
        for attr in ("id", "path"):
            values = [getattr(r, attr) for r in self.rules]
            dupes = sorted({v for v in values if values.count(v) > 1})
            if dupes:
                raise ValueError(f"rule {attr}s must be unique: {', '.join(dupes)}")
        return self

    def rule(self, rule_id: str) -> PostRule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def only(self, rule_ids: set[str]) -> PostPolicy:
        """The same policy narrowed to ``rule_ids``: a process gets only the rules it uses."""
        return PostPolicy(version=self.version, rules=[r for r in self.rules if r.id in rule_ids],
                          sha256=self.sha256)

    def describe(self) -> list[str]:
        return [f"{r.id}: POST {r.path} (effect {r.effect}; approved by {r.approved_by} on {r.approved_on}; "
                f"verified on {', '.join(r.verified_on)})" for r in self.rules]


EMPTY_POLICY = PostPolicy()


def load_policy(path: Path) -> PostPolicy:
    """Loads and validates the POST policy. Refuses a file that others can
    write: whoever can edit it decides what buffmon may send."""
    try:
        st = path.stat()
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise PostPolicyError(f"cannot read POST policy {path}: {exc.strerror or exc}") from exc
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PostPolicyError(
            f"POST policy {path} is writable by group or others (mode {stat.S_IMODE(st.st_mode):04o}); "
            f"make it 0644 or stricter, owned by root or the deploying user"
        )
    try:
        raw = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as exc:
        raise PostPolicyError(f"POST policy {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PostPolicyError(f"POST policy {path} must be a mapping with 'rules'")
    if "sha256" in raw:
        raise PostPolicyError(f"POST policy {path}: 'sha256' is computed from the file, not set in it")
    try:
        return PostPolicy.model_validate({**raw, "sha256": hashlib.sha256(raw_bytes).hexdigest()})
    except ValidationError as exc:
        raise PostPolicyError(f"POST policy {path} is invalid:\n{exc}") from exc
