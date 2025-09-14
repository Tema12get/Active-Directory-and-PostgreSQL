import re

def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Пароль должен содержать минимум 8 символов"
    if not re.search(r"[A-Z]", password):
        return False, "Пароль должен содержать минимум одну заглавную букву"
    if not re.search(r"[a-z]", password):
        return False, "Пароль должен содержать минимум одну строчную букву"
    if not re.search(r"[0-9]", password):
        return False, "Пароль должен содержать минимум одну цифру"
    return True, ""