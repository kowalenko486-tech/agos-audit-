"""AGOS 3.1 Centralized Sensitive Path & File Rules."""
import re
from pathlib import Path
from typing import Union

import unicodedata

# LOW-01 FIX: Extended pattern list covering all required categories
SENSITIVE_PATTERNS = [
    # Environment files
    r"^\.env(\..+)?$",
    # Certificate and key files
    r".*\.pem$",
    r".*\.key$",
    r".*\.p12$",
    r".*\.pfx$",
    r".*\.p8$",
    r".*\.der$",
    r".*\.crt$",
    r".*\.cer$",
    # SSH keys
    r".*id_rsa.*",
    r".*id_ecdsa.*",
    r".*id_ed25519.*",
    r".*id_dsa.*",
    r".*\.ssh[/\\].*",
    r"^\.ssh$",
    # Credential and secret files
    r"^credentials([\._\-].+)?$",
    r"^secrets?([\._\-].+)?$",
    r".*token.*(\.(json|txt|key|yaml|yml))?$",
    r".*passwd.*",
    r".*shadow.*",
    r"^service[\-_]account.*",
    r"^kubeconfig.*",
    r"^\.kube[/\\].*",
    # Package manager credentials
    r"^\.npmrc$",
    r"^\.netrc$",
    r"^\.dockercfg$",
    r"^\.docker[/\\]config\.json$",
    r"^\.pypirc$",
    r"^\.m2[/\\]settings\.xml$",
    # Database and connection files
    r".*connection[\-_]string.*",
    r".*database[\-_]url.*",
    # JWT / signing keys
    r".*jwt[\-_].*\.(key|pem|txt)$",
    r".*signing[\-_].*\.(key|pem|txt)$",
    # Windows credential files
    r".*\.rdg$",
    r".*Credentials[/\\].*",
]

GIT_PATTERNS = [
    r"^\.git(/|\\|$)",
    r".*(/|\\)\.git(/|\\|$)",
]

COMPILED_SENSITIVE = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATTERNS]
COMPILED_GIT = [re.compile(p, re.IGNORECASE) for p in GIT_PATTERNS]


def is_git_internal_path(path: Union[str, Path]) -> bool:
    """Checks whether the path points to or is inside .git/."""
    norm = unicodedata.normalize('NFC', str(path).replace('\\', '/'))
    parts = [p for p in norm.split('/') if p]
    if ".git" in parts:
        return True
    return any(p.search(norm) for p in COMPILED_GIT)


def is_sensitive_path(path: Union[str, Path]) -> bool:
    """
    Checks whether a file path matches sensitive credentials, keys, tokens,
    environment variables, or git internals.
    Uses layered protection: git check + pattern matching on both filename and full path.
    """
    p = Path(path)
    filename = unicodedata.normalize('NFC', p.name)
    normalized_str = unicodedata.normalize('NFC', str(p).replace("\\", "/"))

    if is_git_internal_path(path):
        return True

    for pattern in COMPILED_SENSITIVE:
        if pattern.search(filename) or pattern.search(normalized_str):
            return True

    return False
