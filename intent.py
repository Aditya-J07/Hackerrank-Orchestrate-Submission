import re
# Deletion is the default reading of a privacy request. It is overridden only when the text explicitly
# preserves the account (negated deletion) or asks for a non-deletion service
# (update, export, access, marketing opt-out) and contains no deletion verb.
NEGATED = re.compile(r"(do not (close|delete|remove)|don't (close|delete|remove)|not a request to (delete|close|erase)|"
                     r"without (removing|deleting)|(keep|leave) (the |my )?(account|profile)|marketing lists only|"
                     r"stop the promotional)", re.I)
SERVICE = re.compile(r"(out of date|download|copy of|resetting|misspelled|change the email|what personal information|information held)", re.I)
DELVERB = re.compile(r"(delet|erase|erasure|close (my|this|the) account|remove (my|the|any|records)|suppress|supprim|exclus|elimin|삭제|削除)", re.I)
def wants_deletion(text: str) -> bool:
    if NEGATED.search(text): return False
    if SERVICE.search(text) and not DELVERB.search(text): return False
    return True
