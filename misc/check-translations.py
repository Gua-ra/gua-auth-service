#!/usr/bin/env python3
# Copyright 2026 Gua
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
"""Check the languages the Gua apps ship against English.

For translations/ (server pages) and frontend/locales/ (account app), every
language in LOCALES must:

- have every English key (plural forms are compared by their base key);
- use the same placeholders as English: %(name)s on the server pages,
  {{ name }} and <component> tags in the account app;
- keep protocol jargon (Matrix, MXID, homeserver) out of the text.

Exits non-zero and lists every problem.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCALES = ["pt-BR", "es", "fr"]
CATALOGS = {
    "translations": re.compile(r"%\((\w+)\)[sd]"),
    "frontend/locales": re.compile(r"\{\{\s*(\w+)\s*\}\}|<(\w+)\s*/?>"),
}
PLURAL_FORMS = {"zero", "one", "two", "few", "many", "other"}
JARGON = re.compile(r"\b(matrix|mxid|homeserver)\b", re.IGNORECASE)


def flatten(tree, prefix=""):
    """Map each leaf key, without metadata entries, to its text."""
    leaves = {}
    for key, value in tree.items():
        if key.startswith("@"):
            continue
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            leaves.update(flatten(value, path))
        else:
            leaves[path] = value
    return leaves


def base_key(key):
    """Fold plural forms (`a.b.one`, `a.b:other`) onto their base key."""
    for separator in (":", "."):
        head, _, tail = key.rpartition(separator)
        if head and tail in PLURAL_FORMS:
            return head
    return key


def group(leaves):
    groups = {}
    for key, value in leaves.items():
        groups.setdefault(base_key(key), []).append(value)
    return groups


def placeholders(pattern, texts):
    found = set()
    for text in texts:
        for match in pattern.finditer(text):
            found.add(next(name for name in match.groups() if name))
    return found


def check(catalog, pattern, locale):
    english = group(flatten(json.loads((ROOT / catalog / "en.json").read_text())))
    path = ROOT / catalog / f"{locale}.json"
    translated = group(flatten(json.loads(path.read_text())))
    where = path.relative_to(ROOT)

    problems = []
    for key, texts in english.items():
        if key not in translated:
            problems.append(f"{where}: missing {key}")
            continue
        expected = placeholders(pattern, texts)
        actual = placeholders(pattern, translated[key])
        if expected != actual:
            problems.append(
                f"{where}: {key} uses {sorted(actual)}, English uses {sorted(expected)}"
            )

    for key, texts in translated.items():
        for text in texts:
            if JARGON.search(pattern.sub("", text)):
                problems.append(f"{where}: {key} names the protocol: {text!r}")
    return problems


def main():
    problems = [
        problem
        for catalog, pattern in CATALOGS.items()
        for locale in ["en", *LOCALES]
        for problem in check(catalog, pattern, locale)
    ]
    for problem in problems:
        print(problem)
    if problems:
        print(f"{len(problems)} translation problem(s)")
        return 1
    print("Translations are complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
