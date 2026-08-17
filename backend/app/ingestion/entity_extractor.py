import re
from typing import Any


class EntityExtractor:
    IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    SERVICE_REGEX = re.compile(
        r"The ([\w\-]+) service (?:entered|failed|started|stopped|was)", re.IGNORECASE
    )
    USER_REGEX = re.compile(r"Account Name:\s*([^\s\r\n]+)", re.IGNORECASE)
    FILE_REGEX = re.compile(r"([A-Za-z]:\\[\w\s\.\-\\]+\.\w+)")

    @classmethod
    def extract_entities(cls, message: str) -> dict[str, Any]:
        entities: dict[str, Any] = {}
        if not message:
            return entities

        ips = cls.IP_REGEX.findall(message)
        if ips:
            entities["ip_addresses"] = list(set(ips))

        svc_match = cls.SERVICE_REGEX.search(message)
        if svc_match:
            entities["service_name"] = svc_match.group(1)

        user_match = cls.USER_REGEX.search(message)
        if user_match:
            entities["account_name"] = user_match.group(1)

        files = cls.FILE_REGEX.findall(message)
        if files:
            entities["file_paths"] = list(set(files))

        return entities


# Modül seviyesinde yardımcı sarmalayıcı fonksiyon
def extract_entities(message: str) -> dict[str, Any]:
    return EntityExtractor.extract_entities(message)
