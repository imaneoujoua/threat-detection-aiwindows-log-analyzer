import pytest
import pandas as pd
from src.data_loader import DataLoader

class TestDataLoader:
    """Tests pour le chargeur de données"""
    
    @pytest.fixture
    def sample_csv(self, tmp_path):
        df = pd.DataFrame({
            'duration': [2.5, 0.03],
            'protocol_type': [0, 0],
            'bytes_sent': [480, 42],
            'label': [0, 1]
        })
        csv_file = tmp_path / "test.csv"
        df.to_csv(csv_file, index=False)
        return str(csv_file)
    
    def test_load(self, sample_csv):
        loader = DataLoader(sample_csv)
        data = loader.load()
        assert len(data) == 2
