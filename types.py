class VulnerabilityCheck:
    def __init__(
        self,
        id,
        title,
        severity,
        pattern,
        safe_pattern=None,
        description="",
        suggested_fix="",
    ):
        self.id = id
        self.title = title
        self.severity = severity
        self.pattern = pattern
        self.safe_pattern = safe_pattern
        self.description = description
        self.suggested_fix = suggested_fix

    def __str__(self):
        return f"id={self.id}, title={self.title}, severity={self.severity}, pattern={self.pattern}, safe_pattern={self.safe_pattern}, description={self.description}, suggested_fix={self.suggested_fix})\n"


class VulnerabilityResult:
    def __init__(
        self,
        vulnerability_id,
        file,
        title,
        severity,
        status,
        description,
        fix,
        persistence_of_safe_pattern,
        safe_pattern=None,
    ):
        self.vulnerability_id = vulnerability_id
        self.file = file
        self.title = title
        self.severity = severity
        self.status = status
        self.description = description
        self.fix = fix
        self.persistence_of_safe_pattern = persistence_of_safe_pattern
        self.safe_pattern = safe_pattern

    def __str__(self):
        return f"vulnerability_id={self.vulnerability_id}, file={self.file}, title={self.title}, severity={self.severity}, status={self.status}, description={self.description}, fix={self.fix}, persistence_of_safe_pattern={self.persistence_of_safe_pattern}, safe_pattern={self.safe_pattern})\n"
