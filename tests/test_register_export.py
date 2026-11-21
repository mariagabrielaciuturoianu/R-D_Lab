"""docs/RISK-REGISTER.xlsx must stay an exact export of RISK-REGISTER.md (all risks)."""
import importlib.util
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


def test_template_score_formulas_reproduce_the_markdown_scores():
    for r, row in enumerate(ROWS, start=exporter.FIRST_ROW):
        assert SHEET[f"I{r}"].value == f'=IF(AND(ISNUMBER(G{r}),ISNUMBER(H{r})),G{r}*H{r},"")'
        assert SHEET[f"M{r}"].value == f'=IF(AND(ISNUMBER(K{r}),ISNUMBER(L{r})),K{r}*L{r},"")'
        assert row["L"] * row["I"] == row["Inherent"], f"{row['ID']}: inherent score is not L x I"
        assert row["RL"] * row["RI"] == row["Residual"], f"{row['ID']}: residual score is not RL x RI"
