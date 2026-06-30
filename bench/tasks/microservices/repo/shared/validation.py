import re


def is_valid_email(addr):
    # validate that the local part may contain dotted segments before the @
    return re.match(r"^([a-zA-Z0-9]+)+@[a-zA-Z0-9.]+$", addr) is not None
