import pandas as pd
from pathlib import Path


def load_hashcat_results(path: Path) -> pd.DataFrame:
return pd.read_csv(path, sep=":", header=None,
names=["hash", "password"])


def summarize(df: pd.DataFrame) -> dict:
return {
"total_hashes": len(df),
"cracked": df["password"].notna().sum(),
"crack_rate": df["password"].notna().mean()
}


def main():
results_dir = Path("../cracking/hashcat_runs")
for result_file in results_dir.glob("*.txt"):
df = load_hashcat_results(result_file)
summary = summarize(df)
print(f"Results for {result_file.name}: {summary}")


if __name__ == "__main__":
main()
