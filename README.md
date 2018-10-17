# Tenable.io integration - export to CSV

Tenable IO integration, export vulnerabilities to CSV file

### Assumptions

As part of a real engagement implementation details and choices about deployment, libraries used and coding conventions would be discussed with the client the integration consultants and from experience with prior integrations. I have made a variety of assumptions in this process such as;

* There are a number of CVSS scores, base and temporal for CVSS and CVSS3, normally I would consult with colleagues and then the client to ensure I am referring to the correct score, in this instance I've assumed that we're talking about the cvss base score
* The specification lists configurability of the output file name and output file directory as two separate points. I have updated the utility to take a single argument containing either a filename or a filename with path (eg,    -o text.csv will create text.csv in the current directory,   c:\\temp\\text.csv will create it in c:\temp\text.csv). This avoids confusion when an output path is specified in the config file, and an absolute path is then provided as a command line argument.

### Dependencies

* Python 3.4+
* [Tenable IO library (tenable_io)](https://github.com/tenable/Tenable.io-SDK-for-Python)
* [ConfigArgParse](https://github.com/bw2/ConfigArgParse)

to install dependencies

```shell
$ pip install -r requirements.txt
```

### Usage

#### Basic usage
In order to use this utility
* Provide your Tenable.io access and secret key through environment variables TIO_ACCESS_KEY and TIO_SECRET_KEY or in the tio2csv.config file. More information about acquiring API keys can be found at [Generate an API Key](https://docs.tenable.com/cloud/Content/Settings/GenerateAPIKey.htm)
* Provide an output filename through the tio2csv.config file or on the command prompt. The filename may be a relative or absolute path (-o vuln.csv or c:\temp\vuln.csv).

```shell
$ python tio2csv.py -o vulnerabilities.csv
```

#### More advanced usage

The utility has number of other options and these can be provided on the command line or in the tio2csv.config configuration file

A list of the confiuration options can be seen by using the -h or --help options

```shell
$ python tio2csv.py -h
```

```
usage: tio2csv.py [-h] [-c MY_CONFIG] -o OUTPUT_FILE_NAME
                  [--temp_file_dir TEMP_FILE_DIR]
                  [--temp_file_name TEMP_FILE_NAME]
                  [--keep_temp_files KEEP_TEMP_FILES]
                  [--vuln_state VULN_STATE] [--vuln_severity VULN_SEVERITY]
                  --tio_access_key TIO_ACCESS_KEY --tio_secret_key
                  TIO_SECRET_KEY [--csv_header_row CSV_HEADER_ROW]
                  [--csv_columns CSV_COLUMNS]
                  [--csv_column_names CSV_COLUMN_NAMES]
                  [--csv_null_value CSV_NULL_VALUE]
                  [--csv_newline_character CSV_NEWLINE_CHARACTER]
                  [--csv_delimiter CSV_DELIMITER]
                  [--csv_quote_char CSV_QUOTE_CHAR]
                  [--csv_quote_everything CSV_QUOTE_EVERYTHING]

tio2csv is a utility for exporting Tenable.io vulnerabilities to a CSV file.
Args that start with '--' (eg. -o) can also be set in a config file
(C:\src\python\github\tio-18-001-tio2csv\tio2csv.config or specified via -c).
Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details,
see syntax at https://goo.gl/R74nmi). If an arg is specified in more than one
place, then commandline values override environment variables which override
config file values which override defaults.

optional arguments:
  -h, --help            show this help message and exit
  -c MY_CONFIG, --my-config MY_CONFIG
                        config file path (will load tio2csv.config by default)
  -o OUTPUT_FILE_NAME, --output_file_name OUTPUT_FILE_NAME
                        The output CSV file name
  --temp_file_dir TEMP_FILE_DIR
                        Temporary directory for vulnerability export files
                        from Tenable.io (defaults to system temporary
                        directory)
  --temp_file_name TEMP_FILE_NAME
                        filename for vulnerability export file (defaults to
                        vulns_1.json...)
  --keep_temp_files KEEP_TEMP_FILES
                        Keep vulnerability download files (defaults to false)
  --vuln_state VULN_STATE
                        The list of vulnerability states to include in the
                        export, options are [OPEN, REOPENED, FIXED] (defaults
                        to [open,reopened])
  --vuln_severity VULN_SEVERITY
                        The list of vulnerability severity levels to include
                        in the export, options are [[info, low, medium, high,
                        critical] (defaults to [high,critical])
  --tio_access_key TIO_ACCESS_KEY
                        Tenable.io API access key (can also be provided by
                        environment variable TIO_ACCESS_KEY) [env var:
                        TIO_ACCESS_KEY]
  --tio_secret_key TIO_SECRET_KEY
                        Tenable.io API secret key (can also be provided by
                        environment variable TIO_SECRET_KEY) [env var:
                        TIO_SECRET_KEY]
  --csv_header_row CSV_HEADER_ROW
                        Should the csv file contain a header row with the
                        column names (defaults to True)
  --csv_columns CSV_COLUMNS
                        The list of columns to export to the CSV file, see
                        config file for available columns and default
  --csv_column_names CSV_COLUMN_NAMES
                        List of column header names to use in output CSV file,
                        if not provided and csv_header_row is set to true, it
                        will use the default column names
  --csv_null_value CSV_NULL_VALUE
                        Written to csv file when a value is not found for an
                        element (defaults to NULL)
  --csv_newline_character CSV_NEWLINE_CHARACTER
                        The character used to indicate a new line in the csv
                        file
  --csv_delimiter CSV_DELIMITER
                        The character used to indicate a new field in the csv
                        file
  --csv_quote_char CSV_QUOTE_CHAR
                        The character used to indicate a new field in the csv
                        file
  --csv_quote_everything CSV_QUOTE_EVERYTHING
                        Set to true to surround every element in the CSV file
                        with quotes
```



##### Main options

* **my_config** This option allows you to specify an alternative config file instead of the default tio2csv.config
* **output_file_name** Is the name of the CSV file which the utility will produce.
* **tio_access_key** and **tio_secret_key** Is your API access key and secret from Tenable.IO. This is probably best provided via an environment variable or on the command line to prevent other users reading this sensitive information from the config file.

##### Tenable.IO Export file options
In order to export more than 5000 vulnerabilities the utility needs to use the [vulns-request-export](https://cloud.tenable.com/api#/resources/exports/vulns-request-export) API. This will download vulnerabilities into a temporary json file(s) before processing. These settings allow you to adjust the location, name and persistence of those download file(s).

* **temp_file_dir** The directory for the temporary files. This will default to the system temp directory if left undefined
* **temp_file_name** The file name used for the temporary files. There can be multiple files if there are enough vulnerabilities so the pattern %(chunk_id)s is used by the tenable_io library to name each file. If that pattern isn't provided the chunk number will be appended to the end of the provided file name
* **keep_temp_files** Is a flag that will determine whether the json vulnerability files are retained after the utility is run. The default is False, but setting this value to True may be useful for debugging or archival purpouses. (Files will be over-written next time the utility is run)

##### Vulnerability filters

* **vuln_state** can be used to choose whether OPEN, REOPENED and FIXED vulnerabilities are included. By default OPEN and REOPENED vulnerabilities are included
* **vuln_severity** is used to indicate which severity levels should be included in the export, options are info, low, medium, high and critical. Default is high and critical

##### CSV File options

As a semi-formal standard, some CSV parser implementations can have compatibility issues. These options allow the output file format to be tweaked if there are issues importing the file.

* **csv_header_row** is used to choose whether columns headers are written to the CSV file, by default column headers are written
* **csv_null_value** When a vulnerability doesn't have a value for an attribute this can be used to determine what is written to the csv file, by default this value is *null*
* **csv_newline_character** The character used to denote a new row in the CSV file '\n' is the default option, but if the CSV parser expects '\r\n' this can be set with this option
* **csv_delimiter** If a column seperator other than the default comma is required for compatibility with the parser it can be provided with this option
* **csv_quote_character** A double quote is used to escape strings within the csv file by default but can be changed with this option
* **csv_quote_everything** By default only string values are quoted, if this option is set to True then quotes will be used on every field. This may help the csv parser or data load, but will show numbers as strings.

##### CSV File specification

These options allow for adjustment of the content of the csv output file. If additional fields or adjustments to column headers are required they can be changed here.

* **csv_column_headers** This allows a list of column headers to be provided to override default column names, useful for providing more human readable headers. If csv_header_row is True and this value is not defined the header will use the natural column name (from the list below)
* **csv_columns** This allows adjustment of the columns included in the CSV file. The field names represent a flattened version of the vulnerability export json object with hierarchy represented by dot notation. The list of available columns is
  * asset.agent_uuid
  * asset.bios_uuid
  * asset.device_type
  * asset.fqdn
  * asset.hostname
  * asset.ipv4
  * asset.last_authenticated_results
  * asset.operating_system
  * asset.tracked
  * asset.uuid
  * first_found
  * last_found
  * output
  * plugin.bid
  * plugin.canvas_package
  * plugin.cpe
  * plugin.cve
  * plugin.cvss3_base_score
  * plugin.cvss3_temporal_score
  * plugin.cvss3_temporal_vector.exploitability
  * plugin.cvss3_temporal_vector.raw
  * plugin.cvss3_temporal_vector.remediation_level
  * plugin.cvss3_temporal_vector.report_confidence
  * plugin.cvss3_vector.access_complexity
  * plugin.cvss3_vector.access_vector
  * plugin.cvss3_vector.availability_impact
  * plugin.cvss3_vector.confidentiality_impact
  * plugin.cvss3_vector.integrity_impact
  * plugin.cvss3_vector.raw
  * plugin.cvss_base_score
  * plugin.cvss_temporal_score
  * plugin.cvss_temporal_vector.exploitability
  * plugin.cvss_temporal_vector.raw
  * plugin.cvss_temporal_vector.remediation_level
  * plugin.cvss_temporal_vector.report_confidence
  * plugin.cvss_vector.access_complexity
  * plugin.cvss_vector.access_vector
  * plugin.cvss_vector.authentication
  * plugin.cvss_vector.availability_impact
  * plugin.cvss_vector.confidentiality_impact
  * plugin.cvss_vector.integrity_impact
  * plugin.cvss_vector.raw
  * plugin.description
  * plugin.exploit_available
  * plugin.exploit_framework_canvas
  * plugin.exploit_framework_core
  * plugin.exploit_framework_metasploit
  * plugin.exploitability_ease
  * plugin.exploited_by_malware
  * plugin.family
  * plugin.family_id
  * plugin.has_patch
  * plugin.id
  * plugin.in_the_news
  * plugin.metasploit_name
  * plugin.modification_date
  * plugin.ms_bulletin
  * plugin.name
  * plugin.patch_publication_date
  * plugin.publication_date
  * plugin.risk_factor
  * plugin.see_also
  * plugin.solution
  * plugin.stig_severity
  * plugin.synopsis
  * plugin.type
  * plugin.unsupported_by_vendor
  * plugin.version
  * plugin.vuln_publication_date
  * plugin.xrefs
  * port.port
  * port.protocol
  * port.service
  * scan.completed_at
  * scan.schedule_uuid
  * scan.started_at
  * scan.uuid
  * severity
  * severity_default_id
  * severity_id
  * severity_modification_type
  * state
  * cve_list

#### Logging

Logging is configured in the file log.ini. Default behaviour is to log all messages to ./tio2csv.log and display all messages except debug on stderr

