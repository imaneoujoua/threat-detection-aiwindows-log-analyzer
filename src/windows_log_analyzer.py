import pandas as pd

class WindowsLogAnalyzer:

    def __init__(self):
        pass

    def analyze(self, dataframe):

        report = {
            "total_events": len(dataframe),
            "errors": 0,
            "warnings": 0
        }

        if "Level" in dataframe.columns:

            report["errors"] = len(
                dataframe[dataframe["Level"] == "Error"]
            )

            report["warnings"] = len(
                dataframe[dataframe["Level"] == "Warning"]
            )

        return report
