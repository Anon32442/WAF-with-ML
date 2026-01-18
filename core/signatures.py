import re
ATTACK_PATTERNS = [
    r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)", 
    r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"(?i)union\s+select",
    r"(?i)<script>",
    r"(?i)alert\(",
]

def check_signatures(payload: str) -> bool:
    if not payload: return False
    for pattern in ATTACK_PATTERNS:
        if re.search(pattern, payload):
            return True
    return False