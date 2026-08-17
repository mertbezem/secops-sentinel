import hashlib
import re


class TemplateExtractor:
    """
    Windows Event Log metinlerini deterministik olarak şablonlara indirger.
    Parametre maskeleme regex sırası kritiktir.
    """

    PATTERNS = [
        # 1. Debug ve Dump bloklarını kes
        (re.compile(r"Internal Timing Sequence:.*$", re.IGNORECASE), "Internal Timing Sequence: <TIMING_SEQ>"),
        (re.compile(r"Attached files:.*$", re.IGNORECASE), "Attached files: <FILES>"),
        
        # 2. İşlem Başlıkları ve Yolları
        (re.compile(r"([a-zA-Z0-9_\-\.]+)\s*\(\d+,\s*[A-Z],\s*\d+\)", re.IGNORECASE), "<PROCESS_HEADER>"),
        (re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\s\.\-\\]+\b", re.IGNORECASE), "<REGISTRY>"),
        
        # 3. Standart Benzersiz Tanımlayıcılar
        (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<GUID>"),
        (re.compile(r"\bS-1-\d+(?:-\d+)+\b"), "<SID>"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
        (re.compile(r"0x[0-9a-fA-F]+"), "<HEX>"),
        
        # 4. Dosya Yolları ve Zaman Damgaları
        (re.compile(r"\b[A-Za-z]:\\[\w\s\.\-\\]+\.\w+\b"), "<PATH>"),
        (re.compile(r"\\\\[\w\.\-]+\\[\w\s\.\-\\]+"), "<UNC_PATH>"),
        (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<TIMESTAMP>"),
        
        # 5. Tırnaklı Parametreler ve Sayılar
        (re.compile(r"'[^'\r\n]*'"), "'<PARAM>'"),
        (re.compile(r'"[^"\r\n]*"'), '"<PARAM>"'),
        (re.compile(r"\b\d+\.\d+(?:\.\d+)*\b"), "<VERSION>"),
        (re.compile(r"\b\d+\b"), "<NUM>"),
        (re.compile(r"<NUM>(?:\s+<NUM>)+"), "<NUM>"),
    ]

    @classmethod
    def extract_template(cls, message: str) -> tuple[str, str, int]:
        """
        Mesajı şablona çevirir, hash üretir ve yer tutucu sayısını hesaplar.
        Dönüş: (template_text, template_hash, param_count)
        """
        if not message or not message.strip():
            empty_hash = hashlib.sha256(b"").hexdigest()
            return "<EMPTY>", empty_hash, 0

        clean_text = message.strip()
        param_count = 0

        for pattern, placeholder in cls.PATTERNS:
            matches = len(pattern.findall(clean_text))
            if matches > 0:
                param_count += matches
                clean_text = pattern.sub(placeholder, clean_text)

        # Fazla boşlukları temizle
        clean_text = re.sub(r"\s+", " ", clean_text).strip()
        template_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()

        return clean_text, template_hash, param_count


# Module-level convenience wrapper
def extract_template(message: str) -> tuple[str, str, int]:
    return TemplateExtractor.extract_template(message)
