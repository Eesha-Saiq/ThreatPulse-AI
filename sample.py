
from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent / "datasets" / "uploads"

for filename in ["train_data.csv", "test_data.csv"]:
    source = DATA_DIR / filename
    destination = DATA_DIR / f"sample_{filename}"

    if not source.exists():
        print(f"File not found: {source}")
        continue

    df = pd.read_csv(source, nrows=1000, low_memory=False)
    df.to_csv(destination, index=False)

    print(f"Created: {destination.name}")
    print(f"Rows: {len(df)}")
    print(f"Size: {destination.stat().st_size / (1024 * 1024):.2f} MB")
