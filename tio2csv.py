import os, json, io,argparse
import pandas as pd
import numpy as np
from tenable_io.client import TenableIOClient
from pandas.io.json import json_normalize


__author__ = 'Timothy J. Scott <tim@scott.id.au>'
__version__ = '0.0.1'



def collapse_list(x):
    if type(x['plugin.cve']) is list:
        return ';'.join(x['plugin.cve'])
    else:
        return 'NULL'


# Generate unique name and file.
#test_vulns_json_file = test_file(u'example_export_vulns_%(chunk_id)s.json')




def main():
    '''
    Instantiate an instance of the TenableIOClient.
    '''
    client = TenableIOClient(access_key='0261d1c97111a4e5bca0c1b0d81d87b418b49b567dc0408a2cf117efa608d1d5', secret_key='199ffbaa401258d1a3b474b26df556adf182814b3ad433cb1d303719e9efa107')


    '''
    Export and download vulnerabilities.
    Note: The file name can be optionally parameterized with "%(chunk_id)s" to allow multiple chunks. Otherwise the
        chunk ID will be append to the file name.
    '''

    file_name = 'c:/temp/tio/vulns_%(chunk_id)s.json'

    chunks_available = client.export_helper.download_vulns(path=file_name,num_assets = 3,state=['OPEN','REOPENED'],severity=['high','critical'])

    df = ''
    for chunk_id in chunks_available:
        chunk_file = file_name % {'chunk_id': chunk_id}
        with open(chunk_file) as data_file:
            if(df == ''):
                df = json_normalize(json.load(data_file))
            else:
                df.append(json_normalize(json.load(data_file)))
        
        

    # replace lists of CVE with strings in semi-colon delimited format requested by the spec
    df['cve_list'] = df.apply(collapse_list,axis=1)

    df = df.replace(np.nan,'NULL',regex=True)
    


    columns = ['plugin.name','asset.ipv4','port.port','port.protocol','output','last_found','plugin.cvss_base_score','severity','plugin.id','plugin.solution','first_found','asset.uuid','plugin.exploit_available','cve_list']
    column_names = ['Plugin Name','IPv4 Address','Port','Protocol','Plugin Output','Last Seen Date','CVSS Score','Severity','Plugin ID','Plugin Solution','First Discovered Date','Asset UUID','Exploit Available','CVEs']

    df.to_csv('c:/temp/tio/vulns.csv',columns=columns,header=column_names,index=False)

if __name__ == '__main__':
    main()