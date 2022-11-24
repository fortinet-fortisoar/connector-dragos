""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

PARAM_MAPPING = {
    "Domain": "domain",
    "Filename": "filename",
    "Hostname": "hostname",
    "IP": "ip",
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA256": "sha256",
    "Title": "title",
    "Threat": "threat",
    "TLP": "tlp",
    "Release Date": "release_date",
    "ASC": "true",  # need to check
    "DESC": "false"

}
ENDPOINT_MAPPING = {
    "Product Metadata": 'products/{id}',
    "CSV File": 'products/{id}/csv',
    "STIX2.0 JSON": 'products/{id}/stix2',
}
encode_keys = {'tags': 'tags%5B%5D', 'serial': 'serial%5B%5D', 'serials': 'serials%5B%5D'}
indicator_params = ['page', 'page_size', 'updated_after', 'value', 'type', 'serial', 'tags']
product_params = ['page', 'page_size', 'sort_by', 'sort_desc', 'updated_after', 'serials', 'indicator']
tag_params = ['page', 'page_size', 'tag_type']
