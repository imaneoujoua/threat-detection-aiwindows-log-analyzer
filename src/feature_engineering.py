"""
Feature Engineering module
Create and extract features for threat detection
"""

import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Engineer features for machine learning models
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def create_temporal_features(self, df, datetime_col="TimeCreated"):
        """
        Create temporal features from datetime column
        """

        if datetime_col not in df.columns:
            self.logger.warning(f"Column '{datetime_col}' not found")
            return df

        if not pd.api.types.is_datetime64_any_dtype(df[datetime_col]):
            df[datetime_col] = pd.to_datetime(
                df[datetime_col],
                errors="coerce"
            )

        df["hour_of_day"] = df[datetime_col].dt.hour
        df["day_of_week"] = df[datetime_col].dt.dayofweek
        df["is_weekend"] = (
            df[datetime_col].dt.dayofweek >= 5
        ).astype(int)
        df["month"] = df[datetime_col].dt.month

        self.logger.info("Temporal features created")

        return df

    def create_behavioral_features(self, df):
        """
        Create behavioral features from network data
        """

        if (
            "bytes_sent" in df.columns and
            "bytes_received" in df.columns
        ):
            df["bytes_ratio"] = (
                df["bytes_sent"] /
                (df["bytes_received"] + 1)
            )

            df["total_bytes"] = (
                df["bytes_sent"] +
                df["bytes_received"]
            )

        if (
            "nb_connections" in df.columns and
            "duration" in df.columns
        ):
            duration = np.maximum(
                df["duration"],
                0.01
            )

            df["conn_per_second"] = (
                df["nb_connections"] /
                duration
            )

            if "total_bytes" in df.columns:
                df["bytes_per_connection"] = (
                    df["total_bytes"] /
                    (df["nb_connections"] + 1)
                )

        if (
            "error_rate" in df.columns and
            "nb_connections" in df.columns
        ):
            df["error_count"] = (
                df["error_rate"] *
                df["nb_connections"]
            ).astype(int)

        self.logger.info("Behavioral features created")

        return df

    def create_aggregation_features(
        self,
        df,
        group_by_col=None,
        window_size=10
    ):
        """
        Create rolling aggregation features
        """

        if (
            group_by_col and
            "TimeCreated" in df.columns
        ):

            df = df.sort_values(
                "TimeCreated"
            ).copy()

            numeric_cols = df.select_dtypes(
                include=[np.number]
            ).columns

            for col in numeric_cols:

                df[f"{col}_rolling_mean"] = (
                    df[col]
                    .rolling(
                        window=window_size,
                        min_periods=1
                    )
                    .mean()
                )

                df[f"{col}_rolling_std"] = (
                    df[col]
                    .rolling(
                        window=window_size,
                        min_periods=1
                    )
                    .std()
                    .fillna(0)
                )

        self.logger.info(
            "Aggregation features created"
        )

        return df

    def create_statistical_features(
        self,
        df,
        numeric_cols=None
    ):
        """
        Create statistical features
        """

        if numeric_cols is None:
            numeric_cols = df.select_dtypes(
                include=[np.number]
            ).columns

        for col in numeric_cols:

            std = df[col].std()

            if std == 0 or pd.isna(std):
                std = 1e-8

            df[f"{col}_zscore"] = (
                df[col] - df[col].mean()
            ) / std

            df[f"{col}_percentile"] = (
                df[col].rank(pct=True)
            )

        self.logger.info(
            "Statistical features created"
        )

        return df

    def select_features(
        self,
        df,
        feature_list
    ):
        """
        Select required features
        """

        missing = (
            set(feature_list) -
            set(df.columns)
        )

        if missing:
            self.logger.warning(
                f"Missing features: {missing}"
            )

        available = [
            feature
            for feature in feature_list
            if feature in df.columns
        ]

        return df[available]

    def handle_missing_features(
        self,
        df,
        fill_method="mean"
    ):
        """
        Fill missing values
        """

        numeric_cols = df.select_dtypes(
            include=[np.number]
        ).columns

        for col in numeric_cols:

            if df[col].isnull().any():

                if fill_method == "mean":
                    df[col] = df[col].fillna(
                        df[col].mean()
                    )

                elif fill_method == "median":
                    df[col] = df[col].fillna(
                        df[col].median()
                    )

                elif fill_method == "zero":
                    df[col] = df[col].fillna(0)

        self.logger.info(
            f"Missing features handled using {fill_method}"
        )

        return df

    def normalize_features(
        self,
        df,
        numeric_cols=None,
        method="minmax"
    ):
        """
        Normalize features
        """

        if numeric_cols is None:
            numeric_cols = df.select_dtypes(
                include=[np.number]
            ).columns

        for col in numeric_cols:

            if method == "minmax":

                min_val = df[col].min()
                max_val = df[col].max()

                df[col] = (
                    df[col] - min_val
                ) / (
                    max_val - min_val + 1e-8
                )

            elif method == "zscore":

                df[col] = (
                    df[col] -
                    df[col].mean()
                ) / (
                    df[col].std() + 1e-8
                )

        self.logger.info(
            f"Features normalized using {method}"
        )

        return df

    def get_feature_statistics(self, df):
        """
        Get feature statistics
        """

        numeric_cols = df.select_dtypes(
            include=[np.number]
        ).columns

        stats = {}

        for col in numeric_cols:

            stats[col] = {
                "mean": float(df[col].mean()),
                "std": float(df[col].std()),
                "min": float(df[col].min()),
                "max": float(df[col].max()),
                "median": float(df[col].median()),
                "missing": int(
                    df[col].isnull().sum()
                )
            }

        return stats


if __name__ == "__main__":
    print(
        "FeatureEngineer module loaded successfully"
    )
