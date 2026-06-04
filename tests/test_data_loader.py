from src.data_loader import NetworkLogLoader
import pandas as pd

def test_loader():

    loader = NetworkLogLoader()

    df = pd.DataFrame({
        "a":[1,2,3]
    })

    loader.save_csv(df, "test.csv")

    df2 = loader.load_csv("test.csv")

    assert len(df2) == 3
