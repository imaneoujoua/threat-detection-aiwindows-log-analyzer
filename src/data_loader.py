"""
Data Loader Module
"""

import os
import pandas as pd
import logging

logger = logging.getLogger(__name__)


class NetworkLogLoader:

    def __init__(self):
        self.logger = logging.getLogger(
            self.__class__.__name__
        )

    def load_csv(self, file_path):
        """
        Load CSV file
        """

        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        df = pd.read_csv(file_path)

        self.logger.info(
            f"Loaded {len(df)} records"
        )

        return df

    def save_csv(
        self,
        dataframe,
        file_path
    ):
        """
        Save dataframe to CSV
        """

        directory = os.path.dirname(file_path)

        if directory:
            os.makedirs(
                directory,
                exist_ok=True
            )

        dataframe.to_csv(
            file_path,
            index=False
        )

        self.logger.info(
            f"Saved {len(dataframe)} records"
        )

    def load_excel(
        self,
        file_path
    ):
        """
        Load Excel file
        """

        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        return pd.read_excel(file_path)

    def dataset_info(
        self,
        dataframe
    ):
        """
        Dataset summary
        """

        return {
            "rows": len(dataframe),
            "columns": len(dataframe.columns),
            "column_names": list(dataframe.columns),
            "missing_values":
                dataframe.isnull().sum().to_dict()
        }


if __name__ == "__main__":
    print(
        "NetworkLogLoader module loaded successfully"
    )
