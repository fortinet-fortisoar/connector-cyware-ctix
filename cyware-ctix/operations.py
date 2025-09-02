""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json, time, base64, hashlib, hmac
from connectors.core.connector import get_logger, ConnectorError
logger = get_logger('cyware-ctix')

error_msg = {
    400: "Bad Request -- Your request is invalid.",
    401: "Unauthorized -- Wrong Credentials provided.",
    403: "Access Denied -- The data requested is hidden for administrators only."
         "or your machine time not synchronize with cyware server",
    404: "Not Found -- The specified data could not be found.",
    405: "Method Not Allowed -- You tried to access a API Endpoint with an invalid method.",
    406: "Not Acceptable -- You requested a format that isn't json.",
    410: "Gone -- The data requested has been removed from our servers.",
    429: "Too Many Requests -- You're requesting too frequently! Slow down!",
    500: "Internal Server Error -- We had a problem with our server. Try again later.",
    503: "Service Unavailable -- We're temporarily offline for maintenance. Please try again later.",
    'time_out': 'The request timed out while trying to connect to the remote server',
    'ssl_error': 'SSL certificate validation failed'
}


class CywareCTIX:
    def __init__(self, config):
        self.base_url = config.get('server').strip('/')
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.access_id = config['access_id']
        self.secret_key = config['secret_key']
        self.verify_ssl = config['verify_ssl']
        self.headers = {'content-type': 'application/json'}

    def get_signature(self, expires):
        to_sign = '%s\n%i' % (self.access_id, expires)
        return base64.b64encode(hmac.new(self.secret_key.encode('utf-8'), to_sign.encode('utf-8'),
                                         hashlib.sha1).digest()).decode('utf-8')

    def make_rest_call(self, endpoint, params={}, method='GET'):
        service_endpoint = '{0}{1}'.format(self.base_url, endpoint)
        expires = int(time.time() + 30)
        params['AccessID'] = self.access_id
        params['Expires'] = expires
        params['Signature'] = self.get_signature(expires)
        logger.info('Request URL {}'.format(service_endpoint))
        try:
            response = requests.request(method, service_endpoint, verify=self.verify_ssl, params=params)
            if response.ok:
                return json.loads(response.content.decode('utf-8'))
            if error_msg[response.status_code]:
                raise ConnectorError('{}'.format(error_msg[response.status_code]))
            response.raise_for_status()
        except requests.exceptions.SSLError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(error_msg['time_out']))
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))


def get_current_operation(info_json, action):
    try:
        operation_info = info_json.get('operations')
        exec_action = [action_info for action_info in operation_info if action_info['operation'] == action]
        return exec_action[0]
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def convert_json_response(resp):
    for k, v in resp.items():
        try:
            resp.update({k: json.loads(v)})
        except:
            pass
    return resp


def build_params(params):
    new_params = dict()
    for k, v in params.items():
        if v is not None and v != '':
            if k == "ioc_values":
                new_params[k] = v.split(",")
            elif k == "source":
                new_params[k] = {"source_name": v}
            elif k == "collection":
                new_params[k] = {"collection_name": v}
            else:
                new_params[k] = v
    return new_params


def execute_action(config, params, action_details):
    cyware = CywareCTIX(config)
    endpoint = action_details.get('endpoint')
    params = build_params(params)
    resp = cyware.make_rest_call(endpoint=endpoint, params=params)
    result = resp.get('result')
    if result:
        convert_json_response(result)
    return resp


def _check_health(config):
    cyware = CywareCTIX(config)
    resp = cyware.make_rest_call(endpoint='/ctixapi/openapi/source/')
    if resp:
        logger.info('connector available')
        return True

