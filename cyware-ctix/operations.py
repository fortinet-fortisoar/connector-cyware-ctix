"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import base64
import hashlib
import hmac
import json
import requests
import time
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
        self.base_url = config.get('server', '').strip('/')
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.access_id = config.get('access_id')
        self.secret_key = config.get('secret_key')
        self.verify_ssl = config.get('verify_ssl')
        self.headers = {'content-type': 'application/json'}

    def get_signature(self, expires):
        to_sign = '%s\n%i' % (self.access_id, expires)
        return base64.b64encode(hmac.new(self.secret_key.encode('utf-8'), to_sign.encode('utf-8'),
                                         hashlib.sha1).digest()).decode('utf-8')

    def make_rest_call(self, endpoint, query_params={}, body_params={}, method='GET'):
        service_endpoint = '{0}{1}'.format(self.base_url, endpoint)
        expires = int(time.time() + 30)
        query_params['AccessID'] = self.access_id
        query_params['Expires'] = expires
        query_params['Signature'] = self.get_signature(expires)
        logger.info('Request URL {}'.format(service_endpoint))

        try:
            response = requests.request(method, service_endpoint, verify=self.verify_ssl, params=query_params,
                                        json=body_params)
            if response.ok:
                if response.status_code == 204:
                    return {"status": "success", "message": "No content returned"}
                return response.json()
            if error_msg.get(response.status_code):
                raise ConnectorError('{}'.format(error_msg.get(response.status_code)))
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


def _check_health(config):
    cyware = CywareCTIX(config)
    resp = cyware.make_rest_call(endpoint='/ctixapi/ping/')
    if resp:
        logger.info('connector available')
        return True
    return False


def get_boolean_string(value):
    return 'true' if value else 'false'


def filter_params(params):
    filtered_params = {k: v for k, v in params.items() if v is not None and v != ''}
    return filtered_params


def bulk_ioc_lookup_and_create_intel(config, params):
    cyware = CywareCTIX(config)
    endpoint = "/ctixapi/ingestion/threat-data/bulk-lookup-and-create/"
    body_req_params = {
        'ioc_values': str(params.get('ioc_values')).split(','),
        'source': {'source_name': params.get('source')},
        'collection': {'collection_name': params.get('source')},
        'metadata': params.get('metadata'),
    }
    body_req_params = filter_params(body_req_params)
    query_params = {
        'enrichment': 'true' if params.get('enrichment') else 'false',
        'create': 'true' if params.get('create') else 'false',
    }
    return cyware.make_rest_call(endpoint=endpoint, method='POST', query_params=query_params,
                                 body_params=body_req_params)


def list_threat_data(config, params):
    cyware = CywareCTIX(config)
    endpoint = "/ctixapi/ingestion/threat-data/list/"
    body_req_params = {
        'query': params.get('query')
    }
    query_params = {
        'page': params.get('page', 1),
        'page_size': params.get('page_size', 10),
        'page_limit': params.get('page_limit'),
        'enrichment': params.get('enrichment'),
        'sort': params.get('sort'),
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', query_params=query_params,
                                 body_params=body_req_params)


def bulk_ioc_lookup_advanced(config, params):
    cyware = CywareCTIX(config)
    object_type = params.get('object_type')
    endpoint = f'/ctixapi/ingestion/openapi/bulk-lookup/{object_type}/'
    if params.get('value'):
        body_req_params = {'value': params.get('value').split(',')}
    elif params.get('objectID'):
        body_req_params = {'object_id': params.get('objectID').split(',')}
    else:
        body_req_params = {}
    query_params = {
        'enrichment_data': params.get('enrichment_data'),
        'relation_data': params.get('relation_data'),
        'enrichment_tools': params.get('enrichment_tools'),
        'fields': params.get('fields').split(',')
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', query_params=query_params,
                                 body_params=body_req_params)


def create_intel_via_open_api(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/conversion/quick-intel/open-api/'
    body_req_params = {
        'title': params.get('title'),
        'source': params.get('source'),
        'collection': params.get('collection'),
        'metadata': params.get('metadata'),
        'all_sdos': params.get('allSDOS')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def list_rules(config, params):
    cyware = CywareCTIX(config)
    endpoint = "/ctixapi/ingestion/rules/"
    query_params = {
        'page': params.get('page', 1),
        'page_size': params.get('pageSize', 10),
        'source': params.get('source').split(','),
        'created_by_id': params.get('createdById'),
        'status': params.get('status'),
        'last_active_to': params.get('lastActiveTo'),
        'last_active_from': params.get('lastActiveFrom'),
        'created_from': params.get('createdFrom'),
        'created_to': params.get('createdTo'),
        'is_manual_run': params.get('isManualRun'),
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


def run_rule(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/rules/one-rule/'
    query_params = {
        'end_time': params.get('endTime'),
        'rule': params.get('rule'),
        'start_time': params.get('startTime'),
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


# Get Enrichment Tool List
def enrichment_tools(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/integration/apps/actions/'
    query_params = {
        'action_name': params.get('action_name').split(','),
        'component': params.get('component'),
        'full_list': get_boolean_string(params.get('full_list'))
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


def get_enrichment_object_details(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/enrichment/enrichment-object-detail/'
    query_params = {
        'object_id': params.get('objectID'),
        'object_type': params.get('object_type'),
        'tool_id': params.get('toolID')
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


def get_enriched_threat_data(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/integration/apps/update/threatdata/'
    query_params = {
        'app_slug': params.get('app_slug'),
        'value': params.get('value'),
        'action_slug': params.get('action_slug'),
        'object_id': params.get('objectID'),
        'object_type': params.get('object_type')
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


def list_threat_data_object_details(config, params):
    cyware = CywareCTIX(config)
    object_type = params.get('object_type')
    object_id = params.get('objectID')
    endpoint = f'/ctixapi/ingestion/threat-data/{object_type}/{object_id}/basic/'
    return cyware.make_rest_call(endpoint=endpoint, method='GET')


def threat_data_object_advanced_details(config, params):
    cyware = CywareCTIX(config)
    object_type = params.get('object_type')
    object_id = params.get('object_id')
    endpoint = f'/ctixapi/ingestion/threat-data/{object_type}/{object_id}/advanced-details/'
    return cyware.make_rest_call(endpoint=endpoint, method='GET')


def create_threat_bulletin(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/conversion/threat-bulletin/'
    body_req_params = {
        'title': params.get('title'),
        'description': params.get('description'),
        'status': params.get('status'),
        'tlp': params.get('tlp'),
        'server_collections': params.get('server_collections'),
        'tags': params.get('tags'),
        'attachments': params.get('attachments'),
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def update_threat_bulletin(config, params):
    cyware = CywareCTIX(config)
    threat_bulletin_id = params.get('threat_bulletin_id')
    endpoint = f'/ctixapi/conversion/threat-bulletin/{threat_bulletin_id}/'
    body_req_params = {
        'title': params.get('title'),
        'description': params.get('description'),
        'status': params.get('status'),
        'tlp': params.get('tlp'),
        'server_collections': params.get('server_collections'),
        'tags': params.get('tags'),
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='PUT', body_params=body_req_params)


def add_note_to_threat_data_object(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/notes/'
    body_req_params = {
        'object_id': params.get('object_id'),
        'text': params.get('text'),
        'type': params.get('type'),
        'meta_data': params.get('meta_data'),
        'is_json': params.get('is_json')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def list_relations_of_threat_data_object(config, params):
    cyware = CywareCTIX(config)
    object_id = params.get('objectID')
    object_type = params.get('objectType')
    endpoint = f'/ctixapi/ingestion/threat-data/{object_type}/{object_id}/relations/'
    query_params = {
        'page': params.get('page'),
        'page_size': params.get('page_size'),
        'sources': params.get('sources')
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


def create_tag(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/tags/'
    body_req_params = {
        'name': params.get('name'),
        'colour_code': params.get('colour_code')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def delete_tag(config, params):
    cyware = CywareCTIX(config)
    tag_id = params.get('tag_id').strip()
    endpoint = f'/ctixapi/ingestion/tags/{tag_id}/'
    return cyware.make_rest_call(endpoint=endpoint, method='DELETE')


def list_allowed_indicators(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/conversion/allowed_indicators/'
    method = 'GET'
    query_params = {
        'page': params.get('page'),
        'page_size': params.get('page_size'),
        'type': params.get('type'),
        'created_by_id': params.get('created_by_id'),
        'modified_by_id': params.get('modified_by_id'),
        'created_from': params.get('created_from'),
        'created_to': params.get('created_to'),
        'last_active_from': params.get('last_active_from'),
        'last_active_to': params.get('last_active_to'),
        'sort': params.get('sort')
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


def add_indicators_to_allowed_list(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/conversion/allowed_indicators/'
    body_req_params = {
        'type': params.get('type'),
        'values': params.get('values').split(','),
        'reason': params.get('reason')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def delete_allowed_indicator(config, params):
    cyware = CywareCTIX(config)
    indicator_id = params.get('indicator_id')
    endpoint = f'/ctixapi/conversion/allowed_indicators/{indicator_id}/'
    return cyware.make_rest_call(endpoint=endpoint, method='DELETE')


def bulk_deprecate_undeprecate_objects(config, params):
    cyware = CywareCTIX(config)
    action_type = params.get('action_type','').replace(' ', '_').lower()
    endpoint = f'/ctixapi/ingestion/threat-data/bulk-action/{action_type}/'
    body_req_params = {
        'object_ids': str(params.get('object_ids','')).split(','),
        'object_type': params.get('object_type')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def bulk_mark_unmark_false_positive(config, params):
    cyware = CywareCTIX(config)
    action_type = params.get('action_type', '').replace(' ', '_').lower()
    endpoint = f'/ctixapi/ingestion/threat-data/bulk-action/{action_type}/'
    body_req_params = {
        'object_ids': str(params.get('object_ids')).split(','),
        'object_type': params.get('object_type')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def list_reports(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/reports/'
    query_params = {
        'type': params.get('type'),
        'page': params.get('page'),
        'page_size': params.get('page_size'),
        'repeat_type': params.get('repeat_type'),
        'shared_type': params.get('shared_type'),
        'created_by': params.get('created_by'),
        'modified_by': params.get('modified_by'),
        'created_to': params.get('created_to'),
        'created_from': params.get('created_from'),
        'modified_from': params.get('modified_from'),
        'modified_to': params.get('modified_to'),
        'date_last_run_from': params.get('date_last_run_from'),
        'date_last_run_to': params.get('date_last_run_to')
    }
    query_params = filter_params(query_params)
    return cyware.make_rest_call(endpoint=endpoint, method='GET', query_params=query_params)


def create_report(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/reports/'
    query_params = {'type': 'basic'}
    body_req_params = {
        'name': params.get('name'),
        'type': params.get('type'),
        'basic_report_type': params.get('basic_report_type'),
        'shared_type': params.get('shared_type').lower(),
        'saved_search': params.get('saved_search'),
        'schedule': params.get('schedule'),
        'file_types': params.get('file_types').split(','),
        'columns': params.get('columns'),
        'internal_recipients': params.get('internal_recipients'),
        'query_key': params.get('query_key'),
        'external_recipients': params.get('external_recipients')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', query_params=query_params,
                                 body_params=body_req_params)


def run_report(config, params):
    cyware = CywareCTIX(config)
    report_id = params.get('report_id')
    endpoint = f'/ctixapi/ingestion/reports/{report_id}/run/'
    query_params = {
        'type': params.get('type')
    }
    query_params = filter_params(query_params)
    body_req_params = {
        'starttime': params.get('start_time'),
        'endtime': params.get('end_time'),
        'file_types': params.get('file_types').split(","),
        'internal_recipients': params.get('internal_recipients'),
        'external_recipients': params.get('external_recipients')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', query_params=query_params,
                                 body_params=body_req_params)


def create_custom_attribute(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/configuration/custom-attribute/'
    # Extract type
    type_mapping = {
        "boolean": 0,
        "integer": 1,
        "string": 2,
        "single select": 3,
        "date": 4,
        "json": 5,
        "float": 6
    }

    type_int = type_mapping.get(params.get('type').lower())

    body_req_params = {
        'name': params.get('name'),
        'description': params.get('description'),
        'type': type_int,
        'choices': params.get('choices').split(',') if params.get('choices') else [],
        'is_actionable': params.get('is_actionable'),
        'status': params.get('status'),
        'sdo_objects': params.get('sdo_objects').split(',') if params.get('sdo_objects') else [],
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


def bulk_add_relation(config, params):
    cyware = CywareCTIX(config)
    endpoint = '/ctixapi/ingestion/threat-data/bulk-action/add_relation/'
    body_req_params = {
        'object_ids': params.get('object_ids').split(','),
        'object_type': params.get('object_type'),
        'data': params.get('data')
    }
    body_req_params = filter_params(body_req_params)
    return cyware.make_rest_call(endpoint=endpoint, method='POST', body_params=body_req_params)


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


def convert_json_response(resp):
    for k, v in resp.items():
        try:
            resp.update({k: json.loads(v)})
        except:
            pass
    return resp


def execute_search_indicator(config, params):
    cyware = CywareCTIX(config)
    params = build_params(params)
    resp = cyware.make_rest_call(endpoint='/ctixapi/openapi/search/', query_params=params)
    result = resp.get('result')
    if result:
        convert_json_response(result)
    return resp


def search_domain(config, params):
    return execute_search_indicator(config, params)


def search_ip(config, params):
    return execute_search_indicator(config, params)


def search_url(config, params):
    return execute_search_indicator(config, params)


def search_hash(config, params):
    return execute_search_indicator(config, params)


def search_cve_id(config, params):
    return execute_search_indicator(config, params)


def bulk_lookup_and_create(config, params):
    return execute_search_indicator(config, params)


operations = {
    'bulk_ioc_lookup_and_create_intel': bulk_ioc_lookup_and_create_intel,
    'list_threat_data': list_threat_data,
    'bulk_ioc_lookup_advanced': bulk_ioc_lookup_advanced,
    'create_intel_via_open_api': create_intel_via_open_api,
    'list_rules': list_rules,
    'run_rule': run_rule,
    'enrichment_tools': enrichment_tools,
    'get_enrichment_object_details': get_enrichment_object_details,
    'get_enriched_threat_data': get_enriched_threat_data,
    'list_threat_data_object_details': list_threat_data_object_details,
    'threat_data_object_advanced_details': threat_data_object_advanced_details,
    'create_threat_bulletin': create_threat_bulletin,
    'update_threat_bulletin': update_threat_bulletin,
    'add_note_to_threat_data_object': add_note_to_threat_data_object,
    'list_relations_of_threat_data_object': list_relations_of_threat_data_object,
    'create_tag': create_tag,
    'delete_tag': delete_tag,
    'list_allowed_indicators': list_allowed_indicators,
    'add_indicators_to_allowed_list': add_indicators_to_allowed_list,
    'delete_allowed_indicator': delete_allowed_indicator,
    'bulk_deprecate_undeprecate_objects': bulk_deprecate_undeprecate_objects,
    'bulk_mark_unmark_false_positive': bulk_mark_unmark_false_positive,
    'list_reports': list_reports,
    'create_report': create_report,
    'run_report': run_report,
    'create_custom_attribute': create_custom_attribute,
    'bulk_add_relation': bulk_add_relation,
    'search_domain': search_domain,
    'search_ip': search_ip,
    'search_url': search_url,
    'search_hash': search_hash,
    'search_cve_id': search_cve_id,
    'bulk_lookup_and_create': bulk_lookup_and_create
}
