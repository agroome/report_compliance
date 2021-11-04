import csv
from dotenv import load_dotenv
import logging

import os
import datetime
import pandas as pd
import argparse
import time
from collections import defaultdict, Counter
from functools import partial
from pathlib import Path
from typing import List, Iterable
from tenable.io import TenableIO


def timestamp_from_str(date_string: str, fmt: str = '%Y-%m-%d %H:%M') -> int:
    """Provide date and optional time separated by a space '%m/%d/%Y[ %H:%M]' """
    if ' ' not in date_string:
        date_string = f'{date_string} 00:00'
    try:
        return int(time.mktime(time.strptime(date_string, fmt)))
    except Exception as e:
        SystemExit(repr(e))


env_file = Path(__file__).parent / '.env'
load_dotenv(env_file)

parser = argparse.ArgumentParser()
parser.add_argument('--first-seen', help="first seen date mm/dd/yyyy [hh:mm]")
parser.add_argument('--last-seen', help="last seen date mm/dd/yyyy [hh:mm]")
parser.add_argument('--timeout', help="timeout in seconds, default no timeout")
parser.add_argument('--output-folder', default='.', help="report folders created under this location")
parser.add_argument('--log-level', default='INFO', help="defaults to INFO")
parser.add_argument('--status', default=('ERROR', 'WARNING', 'FAILED'), help="include records with status")
args = parser.parse_args()

numeric_level = getattr(logging, args.log_level.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % args.log_level)

first_seen = timestamp_from_str(args.first_seen) if args.first_seen else None
last_seen = timestamp_from_str(args.last_seen) if args.last_seen else None
timeout = args.timeout if args.timeout else None

dt = datetime.datetime.now()
output_folder = Path(args.output_folder) / str(dt.strftime('%Y-%m-%d'))

logfile = output_folder / 'compliance_export.log'
logging.basicConfig(filename=str(logfile), level=numeric_level)

compliance_fields = [
    'actual_value', 'asset_uuid', 'audit_file', 'check_error', 'check_id', 'check_info', 'check_name',
    'expected_value', 'first_seen', 'last_seen', 'plugin_id', 'reference', 'see_also', 'solution', 'status'
]


def take(number: int, items: Iterable) -> List:
    """Take number items from an iterable and return a list. (rather than load more_itertools)"""

    def take_items():
        for i, item in enumerate(items, start=1):
            yield item
            if i == number:
                break
    logging.debug('returning items')
    return [item for item in take_items()]


def first_item(list_, default=''):
    """Return the first item in a list."""
    return list_ and list_[0] or default


def parse_asset_record(record: dict, tags: List[str] = None) -> tuple:
    """Process asset fields to leave ipv4, fqdn, hostname and any specified tags."""
    out_record = {
        'ipv4': first_item(record['ipv4s']),
        'fqdn': first_item(record['fqdns']),
        'hostname': first_item(record['hostnames']),
    }
    if tags is not None:
        out_record.update({tag['key']: tag['value'] for tag in record['tags'] if tag['key'] in tags})
    return record['id'], out_record


def process_records(records, status=('ERROR', 'WARNING', 'FAILED'), compute_age=True):
    """Computes age for compliance records and reduces records on only those in status argument."""
    included_status = set(status)
    for record in records:
        # only include records when record['status'] is in included_status
        if record['status'] not in included_status:
            continue
        if compute_age:
            _first_seen = pd.to_datetime(record['first_seen'])
            _last_seen = pd.to_datetime(record['last_seen'])
            record['age'] = (_last_seen - _first_seen).days
            record['last_timestamp'] = int(_last_seen.timestamp())

        # some records have missing fields, let's do a copy here
        yield {field: record.get(field, '') for field in compliance_fields}


def inject_fields(records_in: Iterable[dict], payload_dict: dict, on_index: str):
    """Generator that injects fields from payload[index] into record. For use in chaining generators."""

    for record in records_in:
        try:
            # index the related record in payload dict
            yield {**record, **payload_dict[record[on_index]]}
        except KeyError:
            # payload dict is missing the entry for on_index
            fields = ['check_name', 'check_info', 'plugin_id']
            logging.warning(', '.join([f'{field}: {record[field]}' for field in fields]))
            logging.warning(f'payload with id {record[on_index]} not found, continuing')
            yield record


def summarize_compliance(data, summarize_by, include_error=True):
    fields = ['PASSED', 'WARNING', 'FAILED']
    data['count'] = 1
    if include_error:
        fields.append('ERROR')
    _data = (
        data
            .sort_values(by=['last_seen'], ascending=False)
            .groupby(by=['check_name', 'hostname'])
            .first()
            .reset_index()
            .pivot_table(index=summarize_by, columns='status', values='count', fill_value=0, aggfunc='sum')
    )
    _data['TOTAL'] = sum([_data[status] for status in fields])
    for field in fields:
        _data[f'%{field}'] = 100 * _data[field] / _data['TOTAL']
        _data[f'%{field}'].round(decimals=2)
    return _data


def summarize_data(csv_input_file, asset_dictionary, output_file):
    collector = defaultdict(lambda: defaultdict(Counter))
    with open(csv_input_file, newline='') as fobj:
        reader = csv.DictReader(fobj, dialect='excel')
        for row in reader:
            audit_file = row['audit_file']
            asset_uuid = row['asset_uuid']
            collector[audit_file][asset_uuid].update([row['status']])

    field_names = ['audit_file', 'asset_uuid', 'PASSED', 'WARNING', 'FAILED', 'ERROR']
    with open(output_file, 'w', newline='') as fobj:
        writer = csv.DictWriter(fobj, dialect='excel', fieldnames=field_names)
        writer.writeheader()
        for audit_file in collector:
            for uuid in collector['audit_file']:
                record = dict(audit_file=audit_file, asset_uuid=uuid)
                record.update(collector[audit_file][uuid])
                asset = asset_dictionary.get(uuid)
                if asset:
                    record.update(asset)
                writer.writerow(record)


def main():

    if first_seen and not last_seen:
        logging.error('first_seen can only be used in combination with last seen')
        raise SystemExit('ERROR: first_seen can only be used in combination with last seen')

    tags = os.getenv('TAGS', '').split(',')

    if not os.path.exists(output_folder):
        os.mkdir(output_folder)

    tio = TenableIO()

    # parse asset records to reduce included fields and pop list values
    asset_parser = partial(parse_asset_record, tags=tags)
    asset_dictionary = dict(map(asset_parser, tio.exports.assets()))

    asset_fields = ['ipv4', 'fqdn', 'hostname']
    if tags is not None:
        asset_fields.extend(tags)

    # data pipeline export -> process_records -> inject_fields
    records_iterator = (
        inject_fields(
            process_records(
                tio.exports.compliance(first_seen=first_seen, last_seen=last_seen, timeout=timeout), status=('ERROR', 'WARNING', 'FAILED')), asset_dictionary, on_index='asset_uuid'
        )
    )

    fieldnames = compliance_fields + asset_fields + ['age', 'last_timestamp']

    records_per_chunk = 50000

    while True:
        records = take(records_per_chunk, records_iterator)
        if not records:
            break
        df = pd.DataFrame.from_records(records, columns=fieldnames)
        logging.debug(f'writing {len(df)} records')
        if 'audit_file' in df:
            for audit_file, data in df.groupby('audit_file'):
                logging.debug(f'process {len(data)} records from {audit_file}')
                audit_file = str(audit_file).replace('.audit', '.csv')
                data.to_csv(output_folder / audit_file, index=False, mode='a')


if __name__ == '__main__':
    main()
