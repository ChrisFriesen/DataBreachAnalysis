from datetime import date

PWNED_DATA_RECORDS = 456
IIB_DATA_RECORDS = 369
DATE_FIELDS = ["BreachDate"]
DATETIME_FIELDS = ["AddedDate", "ModifiedDate"]
MIN_DATE = date(2009, 1, 1)
MAX_DATE = date(2020, 1, 1)
BREACH_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "Name": {"type": "string"},
            "Title": {"type": "string"},
            "Domain": {"type": "string"},
            "PwnCount": {"type": "number"},
            "Description": {"type": "string"},
            "IsVerified": {"type": "boolean"},
            "IsFabricated": {"type": "boolean"},
            "IsSensitive": {"type": "boolean"},
        },
        "required": ["Domain", "BreachDate", "PwnCount", "IsSensitive", "IsFabricated"]
    }
}