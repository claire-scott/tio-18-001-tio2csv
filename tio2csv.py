import os, json, io, logging, logging.config, configargparse, tempfile, csv, re
import pandas as pd
import numpy as np
from tenable_io.client import TenableIOClient
from pandas.io.json import json_normalize



__author__ = 'Timothy J. Scott <tim@scott.id.au>'
__version__ = '0.0.1'



def collapse_list(cell):
    '''
        mapping function to turn any lists in a dataframe into a string 
        representing the items of the list seperated by a semi colon
    '''
    if type(cell) is list:
        return ';'.join(map(str,cell))
    else:
        return cell


# Generate unique name and file.
#test_vulns_json_file = test_file(u'example_export_vulns_%(chunk_id)s.json')


def get_config():
    '''
        Process configuration options. 
        
        Using ConfigArgParse which is designed
        to be a drop-in replacement for ArgParse providing configuration file
        functionality.
        
        Configuration options will use options provided on the command line
        where provided, followed those provided in the config file, otherwise
        it will fall back to the defaults provided below.
    '''
    cwd = os.getcwd()
    
    parser = configargparse.ArgParser(default_config_files=[os.path.join(cwd,'tio2csv.config')],description='''
        tio2csv is a utility for exporting Tenable.io vulnerabilities to a CSV file.

    ''')

    parser.add('-c','--my-config', is_config_file=True, help='config file path (will load tio2csv.config by default)')

    #parser.add_argument('--output_file_dir', help='The CSV output file directory (defaults to current directory)', default=cwd)
    parser.add_argument('-o','--output_file_name', required=True, help='The output CSV file name')
    
    parser.add_argument('--temp_file_dir', help='Temporary directory for vulnerability export files from Tenable.io (defaults to system temporary directory)',default=tempfile.gettempdir())
    parser.add_argument('--temp_file_name', help='filename for vulnerability export file (defaults to vulns_1.json...)',default='vulns_%(chunk_id)s.json')
    parser.add_argument('--keep_temp_files', type=bool, help='Keep vulnerability download files (defaults to false)', default=False)
    
    parser.add_argument('--vuln_state',action='append',help='The list of vulnerability states to include in the export, options are [OPEN, REOPENED, FIXED] (defaults to [open,reopened])',default=['OPEN','REOPENED'])
    parser.add_argument('--vuln_severity',action='append',help='The list of vulnerability severity levels to include in the export, options are [[info, low, medium, high, critical] (defaults to [high,critical])',default=['high','critical'])
    
    parser.add_argument('--tio_access_key', help='Tenable.io API access key (can also be provided by environment variable TIO_ACCESS_KEY)', required=True, env_var = 'TIO_ACCESS_KEY')
    parser.add_argument('--tio_secret_key', help='Tenable.io API secret key (can also be provided by environment variable TIO_SECRET_KEY)', required=True,env_var = 'TIO_SECRET_KEY')
    
    parser.add_argument('--csv_header_row',type=bool,help='Should the csv file contain a header row with the column names (defaults to True)',default=True)
    parser.add_argument('--csv_columns',action='append',help='The list of columns to export to the CSV file, see config file for available columns and default')
    parser.add_argument('--csv_column_names',action='append',help='List of column header names to use in output CSV file, if not provided and csv_header_row is set to true, it will use the default column names')
    parser.add_argument('--csv_null_value',default='NULL',help='Written to csv file when a value is not found for an element (defaults to ''NULL'')')
  
    # The following options might help if the application has trouble parsing the csv file
    parser.add_argument('--csv_newline_character',default='\n',help='The character used to indicate a new line in the csv file')
    parser.add_argument('--csv_delimiter',default=',',help='The character used to indicate a new field in the csv file')
    parser.add_argument('--csv_quote_char',default='"',help='The character used to indicate a new field in the csv file')
    parser.add_argument('--csv_quote_everything',type=bool,default=False,help='Set to true to surround every element in the CSV file with quotes')
    
    options, _ = parser.parse_known_args()
    
    return options, parser


def get_redacted_parser_values(parser):
    '''
        Logging the arg/config parser information to file will assist debugging
        issues, but we don't want to reveal access keys in the log file. This
        function simply shortens any line referring to the access keys
    '''
    lines = parser.format_values().split('\n')
    
    for i in range(len(lines)):
        if re.match(r'^\s*(tio_access_key|tio_secret_key):.*$',lines[i],re.IGNORECASE):
            lines[i] = lines[i][:25] + '...'
          
    return '\n'.join(lines)



def main():
    
    options, parser = get_config()
    
    #logger = configure_logging(options.log_file_name)
    
    logging.config.fileConfig('log.ini')
    logger = logging.getLogger()
    
    logger.info('Started')

    # Log where each of our values has come from (command line, environment, config file, default)
    logger.debug(get_redacted_parser_values(parser))
    


    client = TenableIOClient(access_key=options.tio_access_key, secret_key=options.tio_secret_key)

    '''
    Export and download vulnerabilities.
    Note: The file name can be optionally parameterized with "%(chunk_id)s" to allow multiple chunks. Otherwise the
        chunk ID will be append to the file name.
    '''
    file_name = os.path.join(options.temp_file_dir,options.temp_file_name)
    
    # The tenable_io library looks for the chunk_id paramater and adds it if
    # if we do that here instead it will be consistent when we try to open the
    # files nexy
        # create a version of the filename that matches the tenable_io library
    if file_name % {'chunk_id': 1} == file_name:
            file_name += '_%(chunk_id)s'
    

    logger.info('About to export vulnerabilities from tenable.io (this may take a few moments)...')
    try:
        # Use one of the tenbale_io library helper functions to start the export and download each of the result files
        chunks_available = client.export_helper.download_vulns(path=file_name,state=options.vuln_state,severity=options.vuln_severity)
    except Exception:
        logger.error('Failed to download vulnerability data', exc_info=True)
        return

    logger.info('completed vulnerabilities export from tenable.io')
    
    df = ''

    for chunk_id in chunks_available:
        logger.info('Loading chunk number {0}'.format(chunk_id))
        # using old style string formatting because that's what the tenable_io library expects
        chunk_file = file_name % {'chunk_id': chunk_id}
        assert(os.path.isfile(chunk_file))
        logger.info('Loading data file {0}'.format(chunk_file))
        with open(chunk_file) as data_file:
            if(df == ''):
                df = json_normalize(json.load(data_file))
            else:
                df.append(json_normalize(json.load(data_file)))
            
        if(options.keep_temp_files == False):
            os.remove(chunk_file)


    # replace lists of CVE with strings in semi-colon delimited format requested by the spec
    df = df.applymap(collapse_list)

    if options.csv_header_row == True:
        if options.csv_column_names is None:
            header = True
        else:
            header = options.csv_column_names
    else:
        header = False

    
    df.to_csv(
            os.path.abspath(options.output_file_name),
            columns=options.csv_columns,
            header=header,
            index=False,
            line_terminator=options.csv_newline_character,
            quotechar=options.csv_quote_char,
            sep=options.csv_delimiter,
            quoting= csv.QUOTE_ALL if options.csv_quote_everything == True else csv.QUOTE_MINIMAL,
            na_rep=options.csv_null_value)
    
    logger.info('Exported {0} vulnerabilities to {1}'.format(len(df),os.path.abspath(options.output_file_name)))
    logger.info('Finished')




if __name__ == '__main__':
    main()