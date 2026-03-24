from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


_DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


@dataclass
class DiffSection:
    header: str
    old_path: str
    new_path: str
    body: list[str]

    def render(self) -> str:
        return self.header + "".join(self.body)


def split_diff_sections(diff_text: str) -> list[DiffSection]:
    lines = diff_text.splitlines(keepends=True)
    sections: list[DiffSection] = []

    current_header: str | None = None
    current_old: str | None = None
    current_new: str | None = None
    current_body: list[str] = []

    for line in lines:
        m = _DIFF_HEADER_RE.match(line.rstrip("\n"))
        if m:
            if current_header is not None and current_old is not None and current_new is not None:
                sections.append(
                    DiffSection(
                        header=current_header,
                        old_path=current_old,
                        new_path=current_new,
                        body=current_body,
                    )
                )
            current_header = line
            current_old = Path(m.group(1)).as_posix()
            current_new = Path(m.group(2)).as_posix()
            current_body = []
        else:
            if current_header is not None:
                current_body.append(line)

    if current_header is not None and current_old is not None and current_new is not None:
        sections.append(
            DiffSection(
                header=current_header,
                old_path=current_old,
                new_path=current_new,
                body=current_body,
            )
        )

    return sections


def prune_diff_by_referenced_files(
    diff_text: str,
    referenced_files: set[str],
    source_extensions: set[str] | None = None,
) -> str:
    if source_extensions is None:
        source_extensions = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}

    kept: list[str] = []

    for section in split_diff_sections(diff_text):
        target_path = section.new_path
        suffix = Path(target_path).suffix.lower()

        if suffix not in source_extensions:
            kept.append(section.render())
            continue

        if target_path in referenced_files:
            kept.append(section.render())

    return "".join(kept)