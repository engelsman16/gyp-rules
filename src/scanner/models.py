from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    raw_snippet: str
    decoded_snippet: str | None
    source_ref: str
    technique: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "raw_snippet": self.raw_snippet,
            "decoded_snippet": self.decoded_snippet,
            "source_ref": self.source_ref,
            "technique": self.technique,
        }
