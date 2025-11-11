# threat_detection/report.py

import json
import os
from datetime import datetime

def generate_report(results: dict, output_dir="reports") -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"{output_dir}/report_{timestamp}.json"

    os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    return output_path
