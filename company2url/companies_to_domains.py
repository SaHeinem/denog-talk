#!/usr/bin/env python3
import argparse, re, socket, sys, time
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


def wd_entity_info(qid: str, languages: list[str]) -> tuple[list[str], list[str]]:
    r = requests.get(f"{WD_ENTITY}{qid}.json", timeout=20)
    if r.status_code != 200:
        return [], []
    ent = r.json().get("entities", {}).get(qid, {})
    claims = ent.get("claims", {})
    website_claims = claims.get("P856", [])  # P856 = official website
    urls = []
    for c in website_claims:
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
    industries = wd_entity_industries(claims.get("P452", []), languages)
    return out, industries


def wd_entity_industries(claims: list[dict], languages: list[str]) -> list[str]:
    if not claims:
        return []
    qids = []
    for c in claims:
        datavalue = ((c.get("mainsnak", {}) or {}).get("datavalue", {}) or {})
        value = datavalue.get("value", {})
        if isinstance(value, dict) and value.get("id"):
            qids.append(value["id"])
    if not qids:
        return []
    labels = wd_fetch_labels(qids, languages)
    seen = set()
    out = []
    for qid in qids:
        label = labels.get(qid)
        if label and label not in seen:
            seen.add(label)
            out.append(label)
    return out


def wd_fetch_labels(qids: list[str], languages: list[str]) -> dict[str, str]:
    params = dict(
        action="wbgetentities",
        ids="|".join(qids),
        props="labels",
        languages="|".join(languages),
        format="json",
        origin="*",
    )
    try:
        r = requests.get(WD_SEARCH, params=params, timeout=20)
    except Exception:
        return {}
    if r.status_code != 200:
        return {}
    entities = r.json().get("entities", {})
    result: dict[str, str] = {}
    for qid, ent in entities.items():
        labels = ent.get("labels", {})
        for lang in languages:
            if lang in labels and "value" in labels[lang]:
                result[qid] = labels[lang]["value"]
                break
        else:
            if labels:
                any_label = next(iter(labels.values()))
                if isinstance(any_label, dict) and "value" in any_label:
                    result[qid] = any_label["value"]
    return result


def pick_preferred(domains: list[str], country: str | None) -> str | None:
    if not domains:
        return None
    preferred_suffixes = [".com"]
    if country:
        preferred_suffixes.append(f".{country.lower()}")
    seen_suffixes = set()
    ordered_suffixes = []
    for suffix in preferred_suffixes:
        if suffix not in seen_suffixes:
            ordered_suffixes.append(suffix)
            seen_suffixes.add(suffix)
    for suffix in ordered_suffixes:
        for d in domains:
            if d.lower().endswith(suffix):
                return d
    return domains[0]


def heuristic(name: str, country: str | None) -> str | None:
    # very conservative fallback: only for simple tokens
    base = re.sub(r"[^a-z0-9-]", "", name.lower())
    if not base or " " in name or len(base) < 3:
        return None
    tlds = [".de", ".com"] if (country and country.upper() == "DE") else [".com", ".de"]
    return base + tlds[0]


def lookup_company(
    company: str, country: str | None = None, sleep_s: float = 0.2
) -> tuple[str | None, list[str]]:
    q = clean_name(company)
    languages = _language_preferences(country)
    # 1) Wikidata search → official website(s)
    ids = wd_search_ids(q, country=country)
    cached_industries: list[str] = []
    for qid in ids:
        domains, industries = wd_entity_info(qid, languages)
        if industries and not cached_industries:
            cached_industries = industries
        if domains:
            pref = pick_preferred(domains, country)
            if pref:
                return pref, industries or cached_industries
        time.sleep(sleep_s)  # be nice to the API
    # 2) conservative heuristic
    return heuristic(q, country), cached_industries


def derive_base_slug(name: str, domain: str | None) -> str | None:
    if domain:
        host = domain.split(".")[0]
        host = re.sub(r"[^a-z0-9-]", "", host.lower())
        if host:
            return host
    cleaned = re.sub(r"[^a-z0-9-]", "", clean_name(name).lower())
    return cleaned or None


def normalize_tld(tld: str) -> str:
    return tld.lower().lstrip(".")


def tld_column_name(tld: str) -> str:
    return f"domain_{tld.replace('.', '_')}"


def probe_tld(
    base_slug: str | None, tld: str, timeout: float
) -> tuple[bool | None, str | None]:
    if not base_slug:
        return None, None
    candidate = f"{base_slug}.{normalize_tld(tld)}"
    exists = domain_resolves(candidate, timeout)
    if exists:
        return True, candidate
    return exists, None


def domain_resolves(domain: str, timeout: float) -> bool:
    default_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(default_timeout)


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
    ap.add_argument(
        "--check-tlds",
        nargs="+",
        metavar="TLD",
        help="Optional list of TLDs to probe (e.g. --check-tlds de com io).",
    )
    ap.add_argument(
        "--tld-timeout",
        type=float,
        default=1.0,
        help="Socket timeout (seconds) for TLD probing (default: 1.0).",
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
    df["domain"] = ""
    df["industry"] = ""
    tld_list = [normalize_tld(t) for t in (args.check_tlds or [])]
    for tld in tld_list:
        df[tld_column_name(tld)] = None

    for idx, name in enumerate(tqdm(companies, desc="Resolving domains")):
        if not name.strip():
            for tld in tld_list:
                df.at[idx, tld_column_name(tld)] = None
            continue
        try:
            d, inds = lookup_company(name, args.country, sleep_s=args.sleep)
        except Exception:
            d, inds = None, []
        domain_value = d
        df.at[idx, "industry"] = "; ".join(inds)
        candidate_domains: list[str] = []
        if tld_list:
            base_slug = derive_base_slug(name, d)
            for tld in tld_list:
                exists, candidate = probe_tld(base_slug, tld, args.tld_timeout)
                df.at[idx, tld_column_name(tld)] = exists
                if exists and candidate:
                    candidate_domains.append(candidate)
        if not domain_value and candidate_domains:
            domain_value = pick_preferred(candidate_domains, args.country)
        df.at[idx, "domain"] = domain_value or ""

    out_path = args.out
    if not out_path:
        base = re.sub(r"\.(csv|xlsx|xls)$", "", args.input, flags=re.I)
        out_path = base + "_domains.csv"
    write_any(df, out_path)
    print(f"Written: {out_path}")


if __name__ == "__main__":
    main()
