#!/usr/bin/env python3
"""Export RISK-REGISTER.md into the course spreadsheet template (docs/RISK-REGISTER.xlsx).

RISK-REGISTER.md stays the source of truth: it is reviewable in pull requests, a binary
spreadsheet is not. This script copies every register row into the input columns of the
template's "Risk Register" sheet and leaves the template's own logic untouched: the
Inherent (I) and Residual (M) score formulas, the colour bands, the red-evidence rule and
the dropdown validations. Excel recalculates the scores when the file is opened.
tests/test_register_export.py fails if the spreadsheet and the Markdown drift apart.

Usage: export_register_xlsx.py [--check]
"""
import re
import sys
from copy import copy
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "RISK-REGISTER.md"
TEMPLATE = ROOT / "docs/archive/Risk_Register_CMG.xlsx"
OUT = ROOT / "docs/RISK-REGISTER.xlsx"
SHEET = "Risk Register"
FIRST_ROW, LAST_ROW = 2, 26  # rows the template formats and validates
OWNER = "Code owner (@mariagabrielaciuturoianu)"

# Markdown column -> spreadsheet column. Inherent (I) and Residual (M) stay formulas.
MD_COLUMNS = ["ID", "Register", "Asset", "Threat", "ATTACK", "Vulnerability", "L", "I",
              "Inherent", "Control", "RL", "RI", "Residual", "Evidence", "Status"]
XL_COLUMN = {"ID": "A", "Register": "B", "Asset": "C", "Threat": "D", "ATTACK": "E",
             "Vulnerability": "F", "L": "G", "I": "H", "Control": "J", "RL": "K", "RI": "L",
             "Evidence": "N", "Status": "P"}
INPUT_COLUMNS = list(XL_COLUMN.values()) + ["O"]
SCORES = {"L", "I", "RL", "RI"}


def plain(text):
    """Markdown cell -> spreadsheet text: drop code ticks and emphasis, keep the words."""
    text = re.sub(r"`([^`]*)`", r"\1", text.strip())
    return re.sub(r"(\*\*|__|\*|_)(\S.*?\S|\S)\1", r"\2", text)


def register_rows(markdown):
    rows = []
    for line in markdown.splitlines():
        if not re.match(r"^\| R-\d+ \|", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) != len(MD_COLUMNS):
            sys.exit(f"{line[:12]}: expected {len(MD_COLUMNS)} cells, found {len(cells)}")
        row = dict(zip(MD_COLUMNS, cells))
        for key in SCORES:
            row[key] = int(row[key])
        row["Inherent"] = int(re.match(r"\d+", row["Inherent"]).group())
        row["Residual"] = int(re.match(r"\d+", row["Residual"]).group())
        rows.append(row)
    return rows


def export(rows):
    if len(rows) > LAST_ROW - FIRST_ROW + 1:
        sys.exit(f"{len(rows)} risks do not fit the template's {LAST_ROW - FIRST_ROW + 1} formatted rows")
    wb = openpyxl.load_workbook(TEMPLATE)
    ws = wb[SHEET]
    for r in range(FIRST_ROW, LAST_ROW + 1):  # remove the template's sample rows
        for col in INPUT_COLUMNS:
            ws[f"{col}{r}"] = None
    for r, row in enumerate(rows, start=FIRST_ROW):
        for key, col in XL_COLUMN.items():
            ws[f"{col}{r}"] = row[key] if key in SCORES else plain(row[key])
        ws[f"O{r}"] = OWNER
    for r in range(FIRST_ROW, LAST_ROW + 1):
        for col, a, b in (("I", "G", "H"), ("M", "K", "L")):  # the template's own formulas
            expected = f'=IF(AND(ISNUMBER({a}{r}),ISNUMBER({b}{r})),{a}{r}*{b}{r},"")'
            cell = ws[f"{col}{r}"]
            if cell.value is None:
                # The template's half-filled sample rows (4-6) lack the formula: restore it,
                # styled like the template's own formula cells further down.
                cell.value = expected
                cell._style = copy(ws[f"{col}{LAST_ROW}"]._style)
            elif cell.value != expected:
                sys.exit(f"template formula changed at {col}{r}: {cell.value!r}")
    wb.calculation.fullCalcOnLoad = True  # Excel computes the score formulas on open
    wb.save(OUT)
    return OUT


if __name__ == "__main__":
    rows = register_rows(SOURCE.read_text())
    if "--check" in sys.argv:
        print(f"{len(rows)} register rows parsed from {SOURCE.name}")
    else:
        print(f"wrote {export(rows).relative_to(ROOT)} with {len(rows)} risks")
