"""
Layer 2: Normalization & Feature Extraction Module
Cleans data, removes infinite/missing values, extracts numeric features, and scales inputs.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from typing import Tuple, List, Optional

class FeatureExtractor:
    def __init__(self, target_col: str = "Label"):
        self.target_col = target_col
        self.scaler = RobustScaler()
        self.feature_names: List[str] = []
        self.is_fitted = False

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace Inf values with NaN and drop/impute missing records."""
        df_clean = df.copy()
        
        # Replace infinity values with NaN
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
        
        # Fill missing values with median for numeric columns
        numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
        df_clean[numeric_cols] = df_clean[numeric_cols].fillna(df_clean[numeric_cols].median())
        
        return df_clean

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray], List[str]]:
        """Clean dataframe, extract numeric features, scale them, and separate target labels."""
        df_clean = self.clean_data(df)
        
        # Separate target label if present
        y = None
        if self.target_col in df_clean.columns:
            y = df_clean[self.target_col].values
            X_df = df_clean.drop(columns=[self.target_col])
        else:
            X_df = df_clean
            
        # Select numeric columns only
        numeric_df = X_df.select_dtypes(include=[np.number])
        self.feature_names = list(numeric_df.columns)
        
        # Fit scaler and transform
        X_scaled = self.scaler.fit_transform(numeric_df)
        self.is_fitted = True
        
        print(f"[✓] Extracted & scaled {X_scaled.shape[1]} numeric features for {X_scaled.shape[0]} samples.")
        return X_scaled, y, self.feature_names

    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Transform new unseen data using fitted scaler."""
        if not self.is_fitted:
            raise ValueError("FeatureExtractor must be fitted before calling transform().")
            
        df_clean = self.clean_data(df)
        
        y = None
        if self.target_col in df_clean.columns:
            y = df_clean[self.target_col].values
            X_df = df_clean.drop(columns=[self.target_col])
        else:
            X_df = df_clean
            
        numeric_df = X_df[self.feature_names]
        X_scaled = self.scaler.transform(numeric_df)
        
        return X_scaled, y
