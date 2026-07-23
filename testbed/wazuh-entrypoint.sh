#!/bin/bash

chown -R wazuh:wazuh /var/ossec/logs

exec /init
