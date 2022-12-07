""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
from .constants import *
import requests
from requests import exceptions as req_exceptions
import arrow

logger = get_logger('dragos')


def get_config(config):
    base_url = config.get('server_url').strip('/')
    if base_url[:7] != 'http://' and base_url[:8] != 'https://':
        base_url = 'https://{}'.format(str(base_url))
    base_url += '/api/v1/'
    api_token = config.get('api_token')
    api_secret = config.get('api_secret')
    verify_ssl = config.get('verify_ssl')
    return base_url, api_token, api_secret, verify_ssl


def make_request(config, endpoint, method='GET'):
    base_url, api_token, api_secret, verify_ssl = get_config(config)
    url = base_url + endpoint
    logger.debug("Requested URL: {0}".format(url))
    header = {
        'accept': '*/*',
        'API-Token': '{0}'.format(api_token),
        'API-Secret': '{0}'.format(api_secret)
    }
    try:
        response = requests.request(method=method, url=url, headers=header, verify=verify_ssl)
        if response.ok:
            if 'json' in response.headers.get('Content-Type').lower():
                return response.json()
            else:
                return response.text
        else:
            logger.error(response.text)
            if response.status_code == 401:
                raise ConnectorError('Unauthorized: Invalid Credentials')
            raise ConnectorError(response.text)
    except req_exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except req_exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except req_exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except req_exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as e:
        raise ConnectorError(e)


def format_date(input_date):
    _date = arrow.get(input_date)
    new_date = _date.format('YYYY-MM-DD HH:mm:ss')
    return new_date.replace(' ', '%20').replace(':', '%3A')


def build_query(params, query_params):
    try:
        q_str_list = []
        for param_key in query_params:
            param_val = params.get(param_key, '')
            if param_key == 'updated_after' and param_val:
                param_val = format_date(param_val)
            if param_key in list(encode_keys.keys()) and param_val:
                param_key = encode_keys.get(param_key)
                param_val = list(map(lambda x: x.strip(' '), param_val.split(","))) if isinstance(param_val,
                                                                                                  str) else param_val
                q_str_list.extend(map(lambda val: '{key}={val}'.format(key=param_key, val=val), param_val))
                continue
            if param_val is not None and param_val != '' and param_val != {} and param_val != []:
                param_val = PARAM_MAPPING.get(param_val, param_val) if not isinstance(param_val, list) else param_val
                q_str_list.append(f'{param_key}={param_val}')
        return '&'.join(q_str_list)
    except Exception as e:
        raise ConnectorError(str(e))


def get_all_indicators(config, params):
    query_params = build_query(params, indicator_params)
    endpoint = 'indicators' + (('?' + query_params) if query_params else '')
    return make_request(config, endpoint)


def get_stix2_indicators(config, params):
    query_params = build_query(params, indicator_params)
    endpoint = 'indicators.stix2' + (('?' + query_params) if query_params else '')
    return make_request(config, endpoint)


def get_cached_stix2_indicators(config, params):
    endpoint = 'indicators/stix2'
    return make_request(config, endpoint)


def get_all_products(config, params):
    query_params = build_query(params, product_params)
    endpoint = 'products' + (('?' + query_params) if query_params else '')
    return make_request(config, endpoint)


def get_product_details(config, params):
    details_of = params.get('details_of')
    product_id = params.get('id')
    endpoint = ENDPOINT_MAPPING.get(details_of).format(id=product_id)
    return make_request(config, endpoint)


def get_all_tags(config, params):
    query_params = build_query(params, tag_params)
    endpoint = 'tags' + (('?' + query_params) if query_params else '')
    return make_request(config, endpoint)


def _check_health(config):
    try:
        params = {
            'page_size': 1
        }
        result = get_all_indicators(config, params)
        if result:
            return True
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)


operations = {
    'get_all_indicators': get_all_indicators,
    'get_stix2_indicators': get_stix2_indicators,
    'get_cached_stix2_indicators': get_cached_stix2_indicators,
    'get_all_products': get_all_products,
    'get_product_details': get_product_details,
    'get_all_tags': get_all_tags
}
