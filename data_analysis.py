import requests
import validation
import constants
import csv
import pandas as pd
import matplotlib as mpl
from pprint import pprint
from datetime import date
from datetime import datetime
from jsonschema import validate


# Cast ISO strings to datetime objects
def cast_pair(pair):
    key, value = pair
    if key in constants.DATE_FIELDS:
        return key, date.fromisoformat(value)
    elif key in constants.DATETIME_FIELDS:
        return key, datetime.fromisoformat(value[:-1])
    else:
        return pair


def pairs_hook(pairs):
    return dict(cast_pair(pair) for pair in pairs)


def fetch_json_data(url):
    resp = requests.get(url)
    if not resp.ok:
        raise SystemExit(f'FAIL: {resp.status_code} - {resp.reason}')

    return resp


def fetch_csv_data(filename):
    data = []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
    return data


def clean_pwned_data(data_response):
    # Validate json structure and cast ISO strings to datetimes
    original_data = data_response.json(object_pairs_hook=pairs_hook)
    validate(instance=original_data, schema=constants.BREACH_SCHEMA)
    return validation.clean_data(original_data, constants.PWNED_DATA_RECORDS)


def clean_iib_data(original_data):
    data = []

    for entry in original_data:
        formatted_entry = {}
        for k, v in entry.items():
            if k == "records":
                formatted_entry[k] = int(v.replace(',', ''))
            elif k == "year":
                formatted_entry[k] = date(int(v), 1, 1)
            elif k == "sensitivity":
                formatted_entry[k] = int(v)
            else:
                formatted_entry[k] = v
        data.append(formatted_entry)

    return validation.clean_data(data, constants.IIB_DATA_RECORDS)


def construct_dataframe(data, columns_to_drop, datetime_fields):
    df = pd.DataFrame(data)
    df = df.drop(columns_to_drop, axis=1)
    for field in datetime_fields:
        df[field] = pd.to_datetime(df[field])
    return df


def main():
    #
    # Collect and sanitize the data
    #

    # Fetch and clean the data from haveibeenpwned
    data_response = fetch_json_data("https://haveibeenpwned.com/api/v3/breaches")
    pwned_data = clean_pwned_data(data_response)
    pprint("Haveibeenpwned data example:")
    pprint(pwned_data[-1])

    # Fetch and clean the data from Information is Beautiful
    loaded_data = fetch_csv_data("DataBreaches.csv")
    iib_data = clean_iib_data(loaded_data)
    pprint("Information is Beautiful data example:")
    pprint(iib_data[-1])

    #
    # Construct dataframes
    #

    # Pwned DataFrame
    pwned_df = construct_dataframe(
        pwned_data,
        ['DataClasses', 'IsRetired', 'IsFabricated', 'IsVerified', 'IsSpamList', 'LogoPath', 'Description'],
        ['BreachDate'])

    # Information is Beautiful DataFrame
    iib_df = construct_dataframe(iib_data, ['description'], ['year'])

    #
    # Plots
    #

    # Pwned dataset by year
    pwn_by_year = pwned_df.groupby(pwned_df.BreachDate.dt.year).size()
    plot_a = pwn_by_year.plot.bar(title="Haveibeenpwned by Year")
    plot_a.set(xlabel="Year",
               ylabel="Number of Breaches")
    mpl.pyplot.show()

    # IIB dataset by year
    iib_by_year = iib_df.groupby(iib_df.year.dt.year).size()
    plot_b = iib_by_year.plot.bar(title="Info is Beautiful by Year")
    plot_b.set(xlabel="Year",
               ylabel="Number of Breaches")
    mpl.pyplot.show()

    # Bucketed record counts
    bins = [0, 100, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000]
    labels = ['Tens', 'Hundreds', 'Thousands', 'Tens of Thousands', 'Hundreds of Thousands',
              'Millions', 'Tens of Millions', 'Hundreds of Millions']

    # Pwned records
    pwn_by_records = pd.cut(pwned_df['PwnCount'], bins, labels=labels)
    pwn_by_records.value_counts(sort=False).plot.bar(
        title="Haveibeenpwned Records", x="Number of Records Breached", y="Number of Breaches")
    mpl.pyplot.show()

    # IIB records
    iib_by_records = pd.cut(iib_df['records'], bins, labels=labels)
    iib_by_records.value_counts(sort=False).plot.bar(
        title="Info is Beautiful Records", x="Number of Records Breached", y="Number of Breaches")
    mpl.pyplot.show()

    # Sensitivity of Breaches
    sensitivity_labels = {1: '1: Email Address',
                          2: '2: SSN or Personal Details',
                          3: '3: Credit Card',
                          4: "4: Personal Records like Health",
                          5: "5: Full Details"}
    colors = ['xkcd:Plum', 'xkcd:Grape', 'xkcd:Purple', 'xkcd:Orchid', 'xkcd:Lavender']
    iib_by_sensitivity = iib_df.groupby(iib_df.sensitivity).size()
    plot_e = iib_by_sensitivity.plot.pie(title="Breach Sensitivity",
                                         labels=sensitivity_labels.values(),
                                         autopct='%1.1f%%',
                                         colors=colors,
                                         counterclock=False,
                                         shadow=True)
    plot_e.axis(False)
    mpl.pyplot.show()


if __name__ == "__main__":
    main()
