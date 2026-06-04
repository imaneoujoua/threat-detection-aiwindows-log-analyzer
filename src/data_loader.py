import pandas as pd

class NetworkLogLoader:

    def load_csv(self, file_path):
        return pd.read_csv(file_path)

    def save_csv(self, dataframe, file_path):
        dataframe.to_csv(file_path, index=False)
