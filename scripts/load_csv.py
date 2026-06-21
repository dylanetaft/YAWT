import pandas as pd
import sqlite3
from typing import List, Optional
import csv

def load_csv(filename: str, delimiter: str, text_delimiter: Optional[str] = None, columns: Optional[List[str]] = None) -> pd.DataFrame:
    if columns is None:
        if not text_delimiter:
            return pd.read_csv(filename, sep=delimiter, header=0, quoting=csv.QUOTE_NONE)
        return pd.read_csv(filename, sep=delimiter, quotechar=text_delimiter, header=0)
    else:
        if not text_delimiter:
            return pd.read_csv(filename, sep=delimiter, header=None, names=columns, quoting=csv.QUOTE_NONE, usecols=columns)
        return pd.read_csv(filename, sep=delimiter, quotechar=text_delimiter, header=None, names=columns, usecols=columns)


def get_distinct_rows(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    return df[columns].drop_duplicates()


def upsert_feature_state(db_path: str, vals: pd.DataFrame) -> pd.DataFrame:
    distinct_vals = get_distinct_rows(vals, ['RFC', 'SECTION'])
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        columns = distinct_vals.columns.tolist()
        
        for _, row in distinct_vals.iterrows():
            conditions = []
            values = []
            for col in columns:
                conditions.append(f"{col} = ?")
                values.append(row[col])
            
            where_clause = " AND ".join(conditions)
            
            cursor.execute(f"""
                INSERT INTO FEATURE_STATE_LOG (RFC, SECTION, REVIEW_DATE, IMPLEMENTED, AI_COMMENT, HUMAN_OPTIONAL, HUMAN_PLANNED, TEST_CASE, HUMAN_COMMENT)
                SELECT RFC, SECTION, REVIEW_DATE, IMPLEMENTED, AI_COMMENT, HUMAN_OPTIONAL, HUMAN_PLANNED, TEST_CASE, HUMAN_COMMENT
                FROM FEATURE_STATE
                WHERE {where_clause}
            """, values)
            
            inserted = cursor.rowcount
            if inserted == 0:
                continue
            
            cursor.execute(f"DELETE FROM FEATURE_STATE WHERE {where_clause}", values)
            
            if cursor.rowcount != inserted:
                raise Exception(f"Row count mismatch: inserted {inserted}, deleted {cursor.rowcount}")
        vals.to_sql('FEATURE_STATE', conn, if_exists='append', index=False)
        conn.commit()
    
    except Exception as e:
        conn.rollback()
        raise e
    
    finally:
        conn.close()


def dump_feature_state(db_path: str, output_file: str = 'ALL_FEATURES.CSV') -> None:
    conn = sqlite3.connect(db_path)
    df = pd.read_sql('SELECT * FROM FEATURE_STATE', conn)
    conn.close()
    df.to_csv(output_file, sep='|', index=False, quoting=csv.QUOTE_NONE)


df = load_csv('findings.csv', delimiter='|', text_delimiter='', columns=['RFC', 'SECTION', 'DESCRIPTION', 'IMPLEMENTED', 'AI_COMMENT'])
upsert_feature_state('features.db', df)

dump_feature_state('features.db', 'ALL_FEATURES.CSV')
