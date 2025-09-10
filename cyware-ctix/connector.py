""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import _check_health, operations

logger = get_logger('cyware-ctix')


class Cyware(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = operations.get(operation)
            logger.info('Executing action {0}'.format(action))
            return action(config, params)
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))

    def check_health(self, config):
        _check_health(config)
