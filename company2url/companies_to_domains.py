#!/usr/bin/env python3
import argparse, re, sys, time
from urllib.parse import urlencode
import requests
import pandas as pd
from tqdm import tqdm

WD_SEARCH = "https://www.wikidata.org/w/api.php"
WD_ENTITY = "https://www.wikidata.org/wiki/Special:EntityData/"

# --- basic normalization of company names (strip legal suffixes etc.)
LEGAL_SUFFIXES = [
    r"\bGmbH\s*&\s*Co\.\s*KG\b",
    r"\bGmbH\b",
    r"\bAG\b",
    r"\bSE\b",
    r"\bUG\b",
    r"\bKG\b",
    r"\bOHG\b",
    r"\bKGaA\b",
    r"\be\.?V\.?\b",
    r"\bInc\.?\b",
    r"\bLtd\.?\b",
    r"\bLLC\b",
    r"\bS\.?A\.?\b",
    r"\bN\.?V\.?\b",
    r"\bS\.?p\.?A\.?\b",
    r"\bOy\b",
    r"\bAB\b",
    r"\bBV\b",
]
LEGAL_SUFFIXES = [re.compile(pat, re.I) for pat in LEGAL_SUFFIXES]


def clean_name(name: str) -> str:
    s = str(name).strip()
    for pat in LEGAL_SUFFIXES:
        s = pat.sub(" ", s)
    s = re.sub(r"[“”\"']", "", s)
    s = re.sub(r"[()]", " ", s)
    s = re.sub(r"\s{2,}", " ", s).strip()
    return s


def to_domain(url: str) -> str | None:
    if not url:
        return None
    try:
        url = url.strip()
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        # very small, dependency-free parse
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0]
        host = host.split("@")[-1]  # drop basic auth if present
        host = host.split(":")[0]  # drop port
        host = re.sub(r"^www\.", "", host, flags=re.I)
        # sanity check: must have a dot
        return host if "." in host else None
    except Exception:
        return None


def _language_preferences(country: str | None) -> list[str]:
    # prefer the local language first, then fall back to English which has good coverage
    if not country:
        return ["de", "en"]
    c = country.upper()
    if c in {"DE", "AT", "CH"}:
        return ["de", "en"]
    return ["en", "de"]


def wd_search_ids(query: str, limit: int = 5, country: str | None = None) -> list[str]:
    for lang in _language_preferences(country):
        params = dict(
            action="wbsearchentities",
            search=query,
            language=lang,
            uselang=lang,
            type="item",
            limit=str(limit),
            format="json",
            origin="*",
        )
        r = requests.get(WD_SEARCH, params=params, timeout=20)
        if r.status_code != 200:
            continue
        data = r.json()
        ids = [x["id"] for x in data.get("search", []) if "id" in x]
        if ids:
            return ids
    return []


def wd_entity_official_domains(qid: str) -> list[str]:
    r = requests.get(f"{WD_ENTITY}{qid}.json", timeout=20)
    if r.status_code != 200:
        return []
    ent = r.json().get("entities", {}).get(qid, {})
    claims = ent.get("claims", {}).get("P856", [])  # P856 = official website
    urls = []
    for c in claims:
        url = ((c.get("mainsnak", {}) or {}).get("datavalue", {}) or {}).get("value")
        if url:
            d = to_domain(url)
            if d:
                urls.append(d)
    # dedupe, keep order
    seen = set()
    out = []
    for d in urls:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def pick_preferred(domains: list[str], country: str | None) -> str | None:
    if not domains:
        return None
    if country and country.upper() == "DE":
        for d in domains:
            if d.lower().endswith(".de"):
                return d
    return domains[0]


def heuristic(name: str, country: str | None) -> str | None:
    # very conservative fallback: only for simple tokens
    base = re.sub(r"[^a-z0-9-]", "", name.lower())
    if not base or " " in name or len(base) < 3:
        return None
    tlds = [".de", ".com"] if (country and country.upper() == "DE") else [".com", ".de"]
    return base + tlds[0]


def lookup_domain(
    company: str, country: str | None = None, sleep_s: float = 0.2
) -> str | None:
    q = clean_name(company)
    # 1) Wikidata search → official website(s)
    ids = wd_search_ids(q, country=country)
    for qid in ids:
        domains = wd_entity_official_domains(qid)
        if domains:
            pref = pick_preferred(domains, country)
            if pref:
                return pref
        time.sleep(sleep_s)  # be nice to the API
    # 2) conservative heuristic
    return heuristic(q, country)


def read_any(path: str) -> pd.DataFrame:
    if path.lower().endswith(".csv"):
        return pd.read_csv(path)
    elif path.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(path)
    else:
        # assume newline-delimited text (one company per line)
        with open(path, "r", encoding="utf-8") as f:
            rows = [line.strip() for line in f if line.strip()]
        return pd.DataFrame({"Company": rows})


def write_any(df: pd.DataFrame, path: str):
    if path.lower().endswith(".csv"):
        df.to_csv(path, index=False)
    elif path.lower().endswith((".xlsx", ".xls")):
        df.to_excel(path, index=False)
    else:
        # default to csv
        df.to_csv(path, index=False)


def main():
    ap = argparse.ArgumentParser(
        description="Append official domains (from Wikidata) next to company names."
    )
    ap.add_argument(
        "input", help="Input file: csv/xlsx/xls or a txt with one company per line"
    )
    ap.add_argument(
        "--name-col",
        default="Company",
        help="Column with company names (default: Company)",
    )
    ap.add_argument("--country", default=None, help="Optional country hint, e.g. DE")
    ap.add_argument(
        "--out",
        default=None,
        help="Output path (csv/xlsx). Default: <input> with _domains suffix.",
    )
    ap.add_argument(
        "--sleep", type=float, default=0.2, help="Delay between requests (seconds)."
    )
    args = ap.parse_args()

    df = read_any(args.input)
    if args.name_col not in df.columns:
        # if there is only one column, treat it as the name column
        if df.shape[1] == 1:
            df.columns = [args.name_col]
        else:
            print(
                f"Column '{args.name_col}' not found. Available: {list(df.columns)}",
                file=sys.stderr,
            )
            sys.exit(1)

    companies = df[args.name_col].astype(str).fillna("").tolist()

    results = []
    for name in tqdm(companies, desc="Resolving domains"):
        if not name.strip():
            results.append("")
            continue
        try:
            d = lookup_domain(name, args.country, sleep_s=args.sleep)
        except Exception:
            d = None
        results.append(d or "")

    df["domain"] = results

    out_path = args.out
    if not out_path:
        base = re.sub(r"\.(csv|xlsx|xls)$", "", args.input, flags=re.I)
        out_path = base + "_domains.csv"
    write_any(df, out_path)
    print(f"Written: {out_path}")


if __name__ == "__main__":
    main()
