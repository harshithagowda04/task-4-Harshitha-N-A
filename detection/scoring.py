"""Risk classifications and verdict policy, shared as named constants."""
def risk_level(score):
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
