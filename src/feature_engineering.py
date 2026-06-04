"""
Feature Engineering module
Create and extract features for threat detection
"""

import pandas as pd
import numpy as np
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class FeatureEngineer:
    """
    Engineer features for machine learning models
    """
    
    def __init__(self):
        """Initialize FeatureEngineer"""
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def create_temporal_features(self, df, datetime_col='TimeCreated'):
        """
        Create temporal features from datetime column
        
        Args:
            df (pd.DataFrame): Input data
            datetime_col (str): Name of datetime column
            
        Returns:
            pd.DataFrame: Data with temporal features
        """
        if datetime_col not in df.columns:
            self.logger.warning(f"Column '{datetime_col}' not found")
            return df
        
        df['hour_of_day'] = df[datetime_col].dt.hour
        df['day_of_week'] = df[datetime_col].dt.dayofweek
        df['is_weekend'] = (df[datetime_col].dt.dayofweek >= 5).astype(int)
        df['month'] = df[datetime_col].dt.month
        
        self.logger.info("Temporal features created")
        return df
    
    def create_behavioral_features(self, df):
        """
        Create behavioral features from network data
        
        Args:
            df (pd.DataFrame): Input data
            
        Returns:
            pd.DataFrame: Data with behavioral features
        """
        # Ratio features
        if 'bytes_sent' in df.columns and 'bytes_received' in df.columns:
            df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_received'] + 1)
            df['total_bytes'] = df['bytes_sent'] + df['bytes_received']
        
        # Connection features
        if 'nb_connections' in df.columns and 'duration' in df.columns:
            df['conn_per_second'] = df['nb_connections'] / (df['duration'] + 0.01)
            df['bytes_per_connection'] = (df.get('total_bytes', 1)) / (df['nb_connections'] + 1)
        
        # Error-related features
        if 'error_rate' in df.columns and 'nb_connections' in df.columns:
            df['error_count'] = (df['error_rate'] * df['nb_connections']).astype(int)
        
        self.logger.info("Behavioral features created")
        return df
    
    def create_aggregation_features(self, df, group_by_col=None, window_size=5):
        """
        Create aggregation features over time windows
        
        Args:
            df (pd.DataFrame): Input data
            group_by_col (str): Column to group by
            window_size (int): Window size in minutes
            
        Returns:
            pd.DataFrame: Data with aggregation features
        """
        if group_by_col and 'TimeCreated' in df.columns:
            # Rolling statistics
            df = df.sort_values('TimeCreated')
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            
            for col in numeric_cols:
                df[f'{col}_rolling_mean'] = df[col].rolling(window=10, min_periods=1).mean()
                df[f'{col}_rolling_std'] = df[col].rolling(window=10, min_periods=1).std()
        
        self.logger.info("Aggregation features created")
        return df
    
    def create_statistical_features(self, df, numeric_cols=None):
        """
        Create statistical features
        
        Args:
            df (pd.DataFrame): Input data
            numeric_cols (list): Numeric columns to process
            
        Returns:
            pd.DataFrame: Data with statistical features
        """
        if numeric_cols is None:
            numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            df[f'{col}_zscore'] = (df[col] - df[col].mean()) / (df[col].std() + 1e-8)
            df[f'{col}_percentile'] = df[col].rank(pct=True)
        
        self.logger.info("Statistical features created")
        return df
    
    def select_features(self, df, feature_list):
        """
        Select specific features from dataframe
        
        Args:
            df (pd.DataFrame): Input data
            feature_list (list): List of feature names
            
        Returns:
            pd.DataFrame: Data with selected features
        """
        missing = set(feature_list) - set(df.columns)
        if missing:
            self.logger.warning(f"Missing features: {missing}")
        
        available = [f for f in feature_list if f in df.columns]
        return df[available]
    
    def handle_missing_features(self, df, fill_method='mean'):
        """
        Handle missing values in features
        
        Args:
            df (pd.DataFrame): Input data
            fill_method (str): 'mean', 'median', 'zero'
            
        Returns:
            pd.DataFrame: Data with filled features
        """
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            if df[col].isnull().any():
                if fill_method == 'mean':
                    df[col].fillna(df[col].mean(), inplace=True)
                elif fill_method == 'median':
                    df[col].fillna(df[col].median(), inplace=True)
                elif fill_method == 'zero':
                    df[col].fillna(0, inplace=True)
        
        self.logger.info(f"Missing features handled with method: {fill_method}")
        return df
    
    def normalize_features(self, df, numeric_cols=None, method='minmax'):
        """
        Normalize features to specific range
        
        Args:
            df (pd.DataFrame): Input data
            numeric_cols (list): Columns to normalize
            method (str): 'minmax' (0-1) or 'zscore'
            
        Returns:
            pd.DataFrame: Data with normalized features
        """
        if numeric_cols is None:
            numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            if method == 'minmax':
                min_val = df[col].min()
                max_val = df[col].max()
                df[col] = (df[col] - min_val) / (max_val - min_val + 1e-8)
            elif method == 'zscore':
                df[col] = (df[col] - df[col].mean()) / (df[col].std() + 1e-8)
        
        self.logger.info(f"Features normalized using {method}")
        return df
    
    def get_feature_statistics(self, df):
        """Get statistics about features"""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        stats = {}
        for col in numeric_cols:
            stats[col] = {
                'mean': df[col].mean(),
                'std': df[col].std(),
                'min': df[col].min(),
                'max': df[col].max(),
                'median': df[col].median(),
                'missing': df[col].isnull().sum()
            }
        
        return stats


if __name__ == "__main__":
    print("FeatureEngineer module loaded successfully")
