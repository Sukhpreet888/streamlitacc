"""
AccountSync — Supabase Backend Helper
Handles all read/write operations to Supabase for the reconciliation app.
"""

import os
import pandas as pd
import numpy as np
from supabase import create_client, Client

# ── Connection ────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://lqhyqkhlwlsxoazousif.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxxaHlxa2hsd2xzeG9hem91c2lmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODA2NzAyOTUsImV4cCI6MjA5NjI0NjI5NX0.ixwF_RCznfEg-MS7_D_loOCQn1fpqWOYB_2-STZ_uHk")

# Known fixed columns (everything else goes into extra_cols jsonb)
FIXED_COLS = {"Post Date", "Debit", "Credit", "All OP Data", "Expense Type", "Name"}
META_COLS  = {"_match_id", "_match_note", "_status", "_matched"}

_client: Client | None = None

def get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _client


# ── Sessions ──────────────────────────────────────────────────────────────────

def create_session(file_name: str) -> str:
    """Create a new session row and return its UUID."""
    client = get_client()
    res = client.table("recon_sessions").insert({"file_name": file_name}).execute()
    return res.data[0]["id"]


def list_sessions() -> list[dict]:
    """Return all sessions ordered by newest first."""
    client = get_client()
    res = client.table("recon_sessions").select("*").order("created_at", desc=True).execute()
    return res.data


def delete_session(session_id: str):
    """Delete a session and all its rows (CASCADE handles rows)."""
    get_client().table("recon_sessions").delete().eq("id", session_id).execute()


# ── Rows ──────────────────────────────────────────────────────────────────────

def _df_row_to_record(session_id: str, row_index: int, row: pd.Series) -> dict:
    """Convert one pandas Series row into a Supabase recon_rows record dict."""
    def _clean(v):
        if v is None or (isinstance(v, float) and np.isnan(v)):
            return None
        return v

    extra = {}
    for col in row.index:
        if col in FIXED_COLS or col in META_COLS:
            continue
        extra[col] = _clean(row[col]) if not isinstance(row[col], (pd.Timestamp,)) else str(row[col])

    post_date = row.get("Post Date")
    if pd.isna(post_date) if hasattr(post_date, '__class__') and post_date.__class__.__name__ in ('NaTType', 'float') else False:
        post_date = None
    elif isinstance(post_date, pd.Timestamp):
        post_date = post_date.strftime("%Y-%m-%d")
    else:
        post_date = str(post_date) if post_date is not None else None

    return {
        "session_id":   session_id,
        "row_index":    row_index,
        "post_date":    post_date,
        "debit":        _clean(row.get("Debit")),
        "credit":       _clean(row.get("Credit")),
        "all_op_data":  str(row.get("All OP Data", "") or ""),
        "expense_type": str(row.get("Expense Type", "") or ""),
        "name":         str(row.get("Name", "") or ""),
        "extra_cols":   extra,
        "match_id":     str(row.get("_match_id", "") or ""),
        "match_note":   str(row.get("_match_note", "") or ""),
        "status":       str(row.get("_status", "") or ""),
    }


def save_dataframe(session_id: str, df: pd.DataFrame, batch_size: int = 500):
    """
    Full replace: delete all existing rows for this session, then bulk-insert
    the current dataframe. Called after every edit so Supabase always matches
    the in-memory state exactly.
    """
    client = get_client()
    # 1. Delete existing rows
    client.table("recon_rows").delete().eq("session_id", session_id).execute()
    # 2. Build records
    records = [
        _df_row_to_record(session_id, i, row)
        for i, row in df.iterrows()
    ]
    # 3. Bulk insert in batches (Supabase has a ~1 MB payload limit per request)
    for start in range(0, len(records), batch_size):
        chunk = records[start:start + batch_size]
        client.table("recon_rows").insert(chunk).execute()


def load_dataframe(session_id: str) -> pd.DataFrame:
    """
    Load all rows for a session from Supabase and reconstruct the DataFrame
    in the same column order the app expects.
    """
    client = get_client()
    # Fetch all rows (paginate if > 1000)
    all_rows = []
    page = 0
    page_size = 1000
    while True:
        res = (
            client.table("recon_rows")
            .select("*")
            .eq("session_id", session_id)
            .order("row_index")
            .range(page * page_size, (page + 1) * page_size - 1)
            .execute()
        )
        all_rows.extend(res.data)
        if len(res.data) < page_size:
            break
        page += 1

    if not all_rows:
        return pd.DataFrame()

    rows = []
    for r in all_rows:
        row = {
            "Post Date":    r["post_date"],
            "Debit":        r["debit"],
            "Credit":       r["credit"],
            "All OP Data":  r["all_op_data"],
            "Expense Type": r["expense_type"],
            "Name":         r["name"],
            "_match_id":    r["match_id"],
            "_match_note":  r["match_note"],
            "_status":      r["status"],
        }
        # Merge back any extra columns stored in jsonb
        extra = r.get("extra_cols") or {}
        row.update(extra)
        rows.append(row)

    df = pd.DataFrame(rows)
    # Restore Post Date as datetime
    if "Post Date" in df.columns:
        df["Post Date"] = pd.to_datetime(df["Post Date"], errors="coerce")
    return df


def upsert_single_row(session_id: str, row_index: int, row: pd.Series):
    """Update a single row by row_index (used for quick edits)."""
    client = get_client()
    record = _df_row_to_record(session_id, row_index, row)
    (
        client.table("recon_rows")
        .update(record)
        .eq("session_id", session_id)
        .eq("row_index", row_index)
        .execute()
    )


def get_match_group(session_id: str, match_id: str) -> pd.DataFrame:
    """Fetch all rows that belong to a specific match_id for Show Match."""
    client = get_client()
    res = (
        client.table("recon_rows")
        .select("*")
        .eq("session_id", session_id)
        .eq("match_id", match_id)
        .order("row_index")
        .execute()
    )
    if not res.data:
        return pd.DataFrame()

    rows = []
    for r in res.data:
        row = {
            "Post Date":    r["post_date"],
            "Debit":        r["debit"],
            "Credit":       r["credit"],
            "All OP Data":  r["all_op_data"],
            "Expense Type": r["expense_type"],
            "Name":         r["name"],
            "_match_id":    r["match_id"],
            "_match_note":  r["match_note"],
            "_status":      r["status"],
        }
        extra = r.get("extra_cols") or {}
        row.update(extra)
        rows.append(row)

    df = pd.DataFrame(rows)
    if "Post Date" in df.columns:
        df["Post Date"] = pd.to_datetime(df["Post Date"], errors="coerce")
    return df
