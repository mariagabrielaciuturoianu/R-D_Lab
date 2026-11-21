"""docs/RISK-REGISTER.xlsx must stay an exact export of RISK-REGISTER.md (all risks)."""
import importlib.util
import re
import zipfile
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("export_register_xlsx", ROOT / "scripts/export_register_xlsx.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)

ROWS = exporter.register_rows((ROOT / "RISK-REGISTER.md").read_text())
SHEET = openpyxl.load_workbook(ROOT / "docs/RISK-REGISTER.xlsx")[exporter.SHEET]


def test_every_markdown_risk_is_in_the_spreadsheet_in_order():
    ids = [SHEET[f"A{r}"].value for r in range(exporter.FIRST_ROW, exporter.LAST_ROW + 1)]
    assert [i for i in ids if i] == [row["ID"] for row in ROWS], "run: make register-xlsx"


def test_spreadsheet_matches_markdown_cell_by_cell():
    for r, row in enumerate(ROWS, start=exporter.FIRST_ROW):
        for key, col in exporter.XL_COLUMN.items():
            want = row[key] if key in exporter.SCORES else exporter.plain(row[key])
            assert SHEET[f"{col}{r}"].value == want, f"{row['ID']} {key} differs: run make register-xlsx"


def test_code_spans_survive_verbatim():
    # Checked against the raw Markdown, independently of exporter.plain(): identifiers such as
    # tests/test_supply_chain.py and pull_request_target must not lose their underscores.
    md_rows = [line for line in (ROOT / "RISK-REGISTER.md").read_text().splitlines()
               if re.match(r"^\| R-\d+ \|", line)]
    for r, line in enumerate(md_rows, start=exporter.FIRST_ROW):
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        row = dict(zip(exporter.MD_COLUMNS, cells))
        for key, col in exporter.XL_COLUMN.items():
            for span in re.findall(r"`([^`]+)`", row[key]):
                assert span in (SHEET[f"{col}{r}"].value or ""), f"{row['ID']} {key}: {span!r} mangled"


def test_workbook_holds_only_the_template_parts():
    # A binary file in a public repository: no hidden sheets, external links or comments.
    wb = SHEET.parent
    assert wb.sheetnames == ["How to use", "Risk Register", "Scales"]
    assert all(ws.sheet_state == "visible" for ws in wb.worksheets)
    assert not list(wb.defined_names)
    parts = zipfile.ZipFile(ROOT / "docs/RISK-REGISTER.xlsx").namelist()
    assert not [p for p in parts if "externalLink" in p or "comments" in p or "vbaProject" in p], parts


def test_check_mode_reports_no_drift():
    assert exporter.drift(ROWS) == [], "run: make register-xlsx"


def test_template_score_formulas_reproduce_the_markdown_scores():
    for r, row in enumerate(ROWS, start=exporter.FIRST_ROW):
        assert SHEET[f"I{r}"].value == f'=IF(AND(ISNUMBER(G{r}),ISNUMBER(H{r})),G{r}*H{r},"")'
        assert SHEET[f"M{r}"].value == f'=IF(AND(ISNUMBER(K{r}),ISNUMBER(L{r})),K{r}*L{r},"")'
        assert row["L"] * row["I"] == row["Inherent"], f"{row['ID']}: inherent score is not L x I"
        assert row["RL"] * row["RI"] == row["Residual"], f"{row['ID']}: residual score is not RL x RI"
