"""
Layer 1: Data Ingestion Module
Handles loading network traffic CSV logs and standardizing input streams.
"""

import pandas as pd
from pathlib import Path
from typing import Union, Dict, Any

class CSVLogLoader:
    def __init__(self, filepath: Union[str, Path]):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found at: {self.filepath}")

    def load(self, sample_size: int = None) -> pd.DataFrame:
        """Load CSV data into Pandas DataFrame with clean column names."""
        print(f"[+] Ingesting data from: {self.filepath.name}")
        
        # Load data
        if sample_size:
            df = pd.read_csv(self.filepath, nrows=sample_size)
        else:
            df = pd.read_csv(self.filepath)
            
        # Strip leading/trailing whitespaces in column names
        df.columns = df.columns.str.strip()
        print(f"[✓] Loaded {len(df)} records with {len(df.columns)} columns.")
        return df

    def get_summary(self) -> Dict[str, Any]:
        """Get quick statistics about the ingested file."""
        df = self.load(sample_size=100)
        return {
            "filename": self.filepath.name,
            "total_columns": len(df.columns),
            "columns": list(df.columns[:10]),
            "preview_rows": len(df)
        }
