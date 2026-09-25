"""Deterministic semantic intent gate for BULL.

Maps natural-language agent requests to capability *hints* using a local,
dependency-free hashed char n-gram k-NN classifier (k=1, cosine over
FNV-1a hashed 3-gram vectors). Safety rules that make this safe to wire
into a fail-closed policy engine:

1. Hints can only NARROW authority or ESCALATE risk, never expand it.
   A destructive-verb floor forbids read-class hints when the request
   text contains destructive verbs; such requests escalate instead.
2. The classifier is deterministic: fixed corpus, seed-free hashing,
   pure arithmetic => identical inputs, identical outputs.
3. Below-confidence matches return no suggestion; callers MUST treat
   that as escalate-or-deny, never as allow.
4. The deterministic policy engine remains the sole authority. This
   module only suggests which Capability a natural-language request
   implies so DECIDE-stage evaluation can bind it exactly.
"""
from __future__ import annotations
import math, re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

_WORD_RE = re.compile(r"[a-z0-9]+")

def _fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

_DIMS = 4096

def _ngrams(text: str, n: int = 3) -> List[str]:
    words = _WORD_RE.findall(text.lower())
    grams: List[str] = []
    for w in words:
        if len(w) < n:
            grams.append(w)
            continue
        for i in range(len(w) - n + 1):
            grams.append(w[i:i+n])
    return grams

def _hash_vec(text: str) -> Dict[int, int]:
    vec: Dict[int, int] = {}
    for g in _ngrams(text):
        idx = _fnv1a32(g.encode("utf-8")) % _DIMS
        vec[idx] = vec.get(idx, 0) + 1
    return vec

def _unit(vec: Dict[int, int]) -> Dict[int, float]:
    norm = math.sqrt(sum(v*v for v in vec.values())) or 1.0
    return {k: v/norm for k, v in vec.items()}

def cosine(a: Dict[int, float], b: Dict[int, float]) -> float:
    if len(a) > len(b): a, b = b, a
    return sum(val * b.get(k, 0.0) for k, val in a.items())

CAPABILITIES = ("FS_READ_PROJECT", "FS_WRITE_PROJECT", "FS_READ_HOME",
                "CREDENTIAL_READ", "SECURITY_CONTROL_WRITE", "PACKAGE_INSTALL",
                "NETWORK_EGRESS", "SHELL_EXEC")
READ_CLASS = frozenset({"FS_READ_PROJECT", "FS_READ_HOME", "CREDENTIAL_READ"})

# Requests containing any of these verbs may never receive a read-class
# hint; they escalate (no suggestion -> caller must escalate or deny).
DESTRUCTIVE_VERBS = frozenset({"delete", "remove", "rm", "drop", "wipe",
    "destroy", "overwrite", "truncate", "shred", "format", "unlink",
    "uninstall", "purge", "kill", "shutdown", "reboot", "chmod", "chown", "revoke"})

# Shipped corpus. Extend via the constructor's `corpus` argument or a
# JSON sidecar; every intent must be a member of CAPABILITIES.
_CORPUS = {
    "FS_READ_PROJECT": [
        "read the config file", "open the readme", "show me the source code",
        "list the files in the project", "cat the log file", "grep the source tree",
        "look at the module contents", "display the file contents",
        "read the test file", "check the file in the repo",
        "grab the readme and summarize it", "view the contents of the file"],
    "FS_WRITE_PROJECT": [
        "write the output file", "save the results to disk", "edit the source file",
        "append to the log", "create a new module", "modify the script",
        "update the file contents", "patch the file",
        "write the report to the project", "delete the temp file",
        "remove the old artifact", "move the file to the build directory"],
    "FS_READ_HOME": [
        "read my ssh keys", "look at the dotfiles in the home directory",
        "open the file in the home folder", "read the user configuration",
        "list the files in my home directory"],
    "CREDENTIAL_READ": [
        "read the api key", "show me the password", "get the secret token",
        "read the credentials file", "print the environment secrets",
        "access the auth token", "show the private key",
        "read the service account key", "read my ssh key"],
    "SECURITY_CONTROL_WRITE": [
        "disable the firewall", "turn off the security policy",
        "change the sandbox settings", "edit the policy file",
        "modify the permission configuration", "remove the access control",
        "update the security rules", "turn off logging",
        "disable the audit trail", "bypass the permission check"],
    "PACKAGE_INSTALL": [
        "install the package", "pip install requests", "apt-get install",
        "add the dependency", "npm install the library",
        "install the toolchain", "download and install the wheel"],
    "NETWORK_EGRESS": [
        "fetch the url", "download the file from the web", "call the api endpoint",
        "send a http request", "curl the website", "post to the webhook",
        "query the remote service", "get the page from the server",
        "fetch the data from the url", "make a request to the endpoint",
        "retrieve the document online", "hit the rest api"],
    "SHELL_EXEC": [
        "run the command", "execute the script", "start the process",
        "launch the binary", "spawn a shell", "run the build",
        "execute the program in the terminal", "run the test suite",
        "compile the program", "start the server"],
}

@dataclass(frozen=True)
class IntentMatch:
    capability: str; score: float; best_example: str

@dataclass(frozen=True)
class SemanticVerdict:
    suggested_capability: Optional[str]; score: float
    matched_example: Optional[str]; reason: str

class SemanticIntentGate:
    def __init__(self, corpus=None, min_confidence=0.35, top_k=3):
        corpus = corpus or _CORPUS
        unknown = set(corpus) - set(CAPABILITIES)
        if unknown: raise ValueError(f"unknown intents: {sorted(unknown)}")
        if not 0 < min_confidence <= 1: raise ValueError("min_confidence in (0,1]")
        empty = [i for i, ex in corpus.items() if not ex]
        if empty: raise ValueError(f"empty corpus for intents: {sorted(empty)}")
        self._min_confidence = min_confidence; self._top_k = top_k
        self._examples = dict(corpus)
        self._pre = {i: [(_unit(_hash_vec(e)), e) for e in ex]
                     for i, ex in corpus.items()}

    def rank(self, text):
        q = _unit(_hash_vec(text))
        out = []
        for intent, pre in self._pre.items():
            best_e, best_s = "", -1.0
            for vec, ex in pre:
                s = cosine(q, vec)
                if s > best_s: best_s, best_e = s, ex
            out.append(IntentMatch(intent, best_s, best_e))
        out.sort(key=lambda m: m.score, reverse=True)
        return out[:self._top_k]

    def evaluate(self, text):
        if not text or not text.strip():
            return SemanticVerdict(None, 0.0, None, "empty request text")
        words = set(_WORD_RE.findall(text.lower()))
        destructive = words & DESTRUCTIVE_VERBS
        ranked = self.rank(text)
        if not ranked: return SemanticVerdict(None, 0.0, None, "no intents loaded")
        top = ranked[0]
        if top.score < self._min_confidence:
            return SemanticVerdict(None, top.score, top.best_example,
                f"top score {top.score:.3f} below floor {self._min_confidence:.3f}; caller must escalate or deny")
        if destructive and top.capability in READ_CLASS:
            return SemanticVerdict(None, top.score, top.best_example,
                f"destructive verb(s) {sorted(destructive)} block read-class hint {top.capability}; caller must escalate or deny")
        return SemanticVerdict(top.capability, top.score, top.best_example,
            f"matched {top.capability} at {top.score:.3f} (example: {top.best_example!r})")
