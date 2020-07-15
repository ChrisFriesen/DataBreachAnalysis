import constants
from datetime import date


def validate_count(value):
    assert value > 0, f"Invalid number of affected accounts: {value}"


def validate_fabricated(value):
    assert not value, "Breach was fabricated"


def validate_verified(value):
    assert value, "Breach was not verified"


def validate_breach_date(value):
    assert constants.MIN_DATE <= value < constants.MAX_DATE, f"Breach outside of examined range date: {value}"


def validate_sensitivity(value):
    assert 1 <= value <= 5, f'Sensitivity ranked outside of defined param: {value}'


def validate_entry(e):
    validators = [
        ('PwnCount', validate_count),
        ('IsFabricated', validate_fabricated),
        ('IsVerified', validate_verified),
        ('BreachDate', validate_breach_date),
        ('year', validate_breach_date),
        ('records', validate_count),
        ('sensitivity', validate_sensitivity)
    ]

    for attr, validator in validators:
        if attr in e:
            value = e[attr]
            if validator:
                try:
                    validator(value)
                except AssertionError as e:
                    # print(e)      # For debugging purposes
                    return False
    return True


def clean_data(data, known_data_records):
    # Ensure the amount of rows is within what is expected
    num_records = len(data)
    print(f'Total number of breaches returned: {num_records}')
    if num_records < known_data_records or num_records > 5000:
        raise ValueError('Not the expected number of data records')

    # Remove any rows that are invalid
    cleaned_data = [entry for entry in data if validate_entry(entry)]
    print(f'Total number of breaches usable: {len(cleaned_data)}')

    return cleaned_data
