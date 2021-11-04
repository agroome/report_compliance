# report_compliance
export and report on tenable compliance data

## install
```
pip install -r requirements.txt
```

## run
```
usage: python report_compliance.py [-h] [--first-seen FIRST_SEEN] [--last-seen LAST_SEEN] [--timeout TIMEOUT] [--output-folder OUTPUT_FOLDER] [--log-level LOG_LEVEL] 

optional arguments:
  -h, --help            show this help message and exit
  --first-seen FIRST_SEEN
                        first seen date mm/dd/yyyy [hh:mm]
  --last-seen LAST_SEEN
                        last seen date mm/dd/yyyy [hh:mm]
  --timeout TIMEOUT     timeout in seconds, default no timeout
  --output-folder OUTPUT_FOLDER
                        report folders created under this location
  --log-level LOG_LEVEL
                        defaults to INFO

```
