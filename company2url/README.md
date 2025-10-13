# Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install pandas requests openpyxl tqdm
```

# input.csv file

have file with e.g.

```csv
Company
"Company Name in Quotes"
```

# Usage

```bash
python companies_to_domains.py input.csv --name-col Company --country DE --out output.csv
```

If you want to probe additional TLDs and capture industry labels, append flags such as:

```bash
python companies_to_domains.py input.csv --check-tlds de com io --tld-timeout 1.5
```
