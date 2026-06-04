```python
"""
Data Preprocessor Module
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler


class DataPreprocessor:

    def __init__(self):
        self.scaler = StandardScaler()

    def handle_missing_values(
        self,
        df,
        strategy="mean"
    ):
        """
        Fill missing values
        """

        numeric_cols = df.select_dtypes(
            include=[np.number]
        ).columns

        for col in numeric_cols:

            if df[col].isnull().any():

                if strategy == "mean":
                    df[col] = df[col].fillna(
                        df[col].mean()
                    )

                elif strategy == "median":
                    df[col] = df[col].fillna(
                        df[col].median()
                    )

                elif strategy == "zero":
                    df[col] = df[col].fillna(0)

        return df

    def remove_duplicates(
        self,
        df
    ):
        """
        Remove duplicate rows
        """

        return df.drop_duplicates()

    def fit_transform(
        self,
        X
    ):
        """
        Fit scaler and transform
        """

        return self.scaler.fit_transform(X)

    def transform(
        self,
        X
    ):
        """
        Transform using fitted scaler
        """

        return self.scaler.transform(X)

    def inverse_transform(
        self,
        X
    ):
        """
        Reverse scaling
        """

        return self.scaler.inverse_transform(X)


if __name__ == "__main__":
    print(
        "DataPreprocessor module loaded successfully"
    )
```

