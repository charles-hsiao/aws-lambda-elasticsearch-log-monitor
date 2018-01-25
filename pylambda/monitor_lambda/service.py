# -*- coding: utf-8 -*-
from __future__ import division
import boto3
import re
import requests
import json
from botocore.exceptions import ClientError
import config


def dynamodb_scan(dynamo_client, table_name):
    table = dynamo_client.Table(table_name)
    try:
        response = table.scan()
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        if 'Items' not in response:
            return None
        else:
            item = response['Items']
            return item
    return None


def dynamodb_insert_data(dynamodb, table_name, content_arr):
    result = False
    table = dynamodb.Table(table_name)
    try:
        insert_result = table.put_item(
            Item=content_arr
        )
        if insert_result['ResponseMetadata']['HTTPStatusCode'] == 200:
            result = True
    except ClientError as e:
        print(e.response['Error']['Message'])

    return result


'''
dynamodb = boto3.resource("dynamodb",
                          aws_access_key_id=config.aws_access_key_id,
                          aws_secret_access_key=config.aws_secret_access_key,
                          region_name=config.aws_region)
content_arr = {
      "monitor_id": "TEST2",
      "alert": False,
      "warning": False
    }

insert_result = dynamodb_insert_data(dynamodb, config.table_name_current, content_arr)
print insert_result
'''


def dynamodb_read_pkey(dynamo_client, table_name, key, index):
    table = dynamo_client.Table(table_name)
    try:
        response = table.get_item(
            Key={
                key: str(index)
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        if 'Item' not in response:
            return None
        else:
            item = response['Item']
            return item
    return None


'''
dynamo_client = boto3.resource("dynamodb",
                          aws_access_key_id=config.aws_access_key_id,
                          aws_secret_access_key=config.aws_secret_access_key,
                          region_name=config.aws_region)


item = dynamodb_read_pkey(dynamo_client, config.table_name_current, 'monitor_id', 'Cyclops-Beta-SignIn_FailedRate')
print item
'''


def dynamodb_delete_item(dynamo_client, table_name, key, value):
    table = dynamo_client.Table(table_name)
    try:
        table.delete_item(
            Key={
                key: value
            }
        )
    except ClientError as e:
        return False
    else:
        return True


'''
dynamo_client = boto3.resource("dynamodb",
                               aws_access_key_id=config.aws_access_key_id,
                               aws_secret_access_key=config.aws_secret_access_key,
                               region_name=config.aws_region)
delete_result = dynamodb_delete_item(dynamo_client, config.table_name_current, 'monitor_id', 'TEST2')
print delete_result
'''


def get_log_hit(elk_conn, json_data):
    r = requests.post(elk_conn + "?size=0", data=json_data)
    json_res = json.loads(r.text)
    return json_res['hits']['total']


def get_log_dict_value(elk_conn, json_data, value_param):

    r = requests.post(elk_conn + "?size=0", data=json_data)
    json_res = json.loads(r.text)

    dict_list = value_param.split(".")

    str_key = ""
    for key in dict_list:
        str_key += '[\'' + key + '\']'

    return eval("json_res" + str_key)


def slack_notify(slack_webhook, post_data):
    r = requests.post(slack_webhook, data=post_data)
    if r == '200':
        return True
    else:
        return False

#post_data = {"text": "Test"}
#slack_notify("http://SLACK_WEB_HOOK_URL", json.dumps(post_data))


def monitor_current_update(monitor_id, alarm_level, alarm_bool):
    dynamo_client = boto3.resource("dynamodb",
                                   aws_access_key_id=config.aws_access_key_id,
                                   aws_secret_access_key=config.aws_secret_access_key,
                                   region_name=config.aws_region)
    table = dynamo_client .Table(config.table_name_current)
    try:
        table.update_item(
            Key={
                'monitor_id': monitor_id
            },
            UpdateExpression="set " + alarm_level + " = :p",
            ExpressionAttributeValues={
                ':p': alarm_bool
            },
            ReturnValues="UPDATED_NEW"
        )
    except ClientError:
        return False
    else:
        return True


def check_monitor_current_status(monitor_id, alarm_level):
    dynamo_client = boto3.resource("dynamodb",
                                   aws_access_key_id=config.aws_access_key_id,
                                   aws_secret_access_key=config.aws_secret_access_key,
                                   region_name=config.aws_region)

    item = dynamodb_read_pkey(dynamo_client, config.table_name_current, 'monitor_id', monitor_id)
    if item is not None:
        return item[alarm_level]
    else:
        return None


#r = check_monitor_current_status('TEST2', 'warning')
#print r


def handle_monitor_current(monitor_id, alarm_level, alarm_bool):
    alarm_status = "NoChange"  # NoChange; Recovered; Start
    dynamodb = boto3.resource("dynamodb",
                              aws_access_key_id=config.aws_access_key_id,
                              aws_secret_access_key=config.aws_secret_access_key,
                              region_name=config.aws_region)

    current_status = check_monitor_current_status(monitor_id, alarm_level)
    if current_status is True:
        if alarm_bool is False:
            monitor_current_update(monitor_id, alarm_level, alarm_bool)
            alarm_status = "Recovered"
    elif current_status is False:
        if alarm_bool is True:
            monitor_current_update(monitor_id, alarm_level, alarm_bool)
            alarm_status = "Start"
    elif current_status is None:
        if alarm_level == 'warning':
            content_arr = {
                "monitor_id": monitor_id,
                'warning': alarm_bool,
                'alert': False
            }
        elif alarm_level == 'alert':
            content_arr = {
                "monitor_id": monitor_id,
                'warning': False,
                'alert': alarm_bool
            }
        dynamodb_insert_data(dynamodb, config.table_name_current, content_arr)
        if alarm_bool is True:
            alarm_status = "Start"

    return alarm_status


# NoChange; Recovered; Start
#alarm_status = handle_monitor_current("TEST3", "warning", True)
#print alarm_status


def handle_notify(monitor_id, cal_result, config_alarms, config_notify, alarm_status_warning, alarm_status_alert):
    send_notify = ""
    #print "[bool_warning]" + str(bool_warning) + "[alarm_status_warning]" + alarm_status_warning + "[bool_alert]" + str(bool_alert) + "[alarm_status_alert]" + alarm_status_alert
    # alarm_status: NoChange; Recovered; Start
    # Warning
    if alarm_status_warning != 'NoChange':
        send_notify = "warning"
        # Slack Notify
        if 'slack' in config_notify:
            slack_webhook = config_notify['slack']
            warning_data = {"text": "[" + alarm_status_warning + "]" + "[WARN] " + monitor_id + ": " + str(cal_result) + config_alarms['warning']}
            slack_notify(slack_webhook, json.dumps(warning_data))

    # Alert
    if alarm_status_alert != 'NoChange':
        send_notify += "alert"
        # Slack Notify
        if 'slack' in config_notify:
            slack_webhook = config_notify['slack']
            alert_data = {"text": "[" + alarm_status_alert + "]" + "[ALERT] " + monitor_id + ": " + str(cal_result) + config_alarms['alert']}
            slack_notify(slack_webhook, json.dumps(alert_data))

    return send_notify


def handler(event, context):
    dynamo_client = boto3.resource("dynamodb",
                                   aws_access_key_id=config.aws_access_key_id,
                                   aws_secret_access_key=config.aws_secret_access_key,
                                   region_name=config.aws_region)
    items = dynamodb_scan(dynamo_client, config.table_name_config)
    return_list = []

    for i in range(len(items)):
        enable = items[i]['enable']
        if enable:
            monitor_id = items[i]['monitor_id']

            elk_env = items[i]['elk_env']
            if elk_env == 'staging':
                elk_conn = config.elk_stg
            elif elk_env == 'production':
                elk_conn = config.elk_prod

            formula = items[i]['formula']

            # Replace ${} params
            pattern = re.compile(r'\$\{([A-Za-z0-9_.]+)\}')
            params = re.findall(pattern, formula)
            dict_log_count = {}
            for param in params:
                param_log_count = get_log_hit(elk_conn, json.dumps(items[i]['parameters'][param]))
                dict_log_count.update({"${"+param+"}": param_log_count})

            # Replace %{} params
            pattern_2 = re.compile(r'%\{([A-Za-z0-9_.]+)\}')
            params_2 = re.findall(pattern_2, formula)
            dict_log_value = {}
            for param in params_2:
                param_log_value = get_log_dict_value(elk_conn, json.dumps(items[i]['parameters'][param]), param)
                dict_log_value.update({"%{"+param+"}": param_log_value})

            # Replace formula for calculation
            formula_replaced = formula

            for key, value in dict_log_count.iteritems():
                formula_replaced = formula_replaced.replace(key, str(value))

            for key, value in dict_log_value.iteritems():
                formula_replaced = formula_replaced.replace(key, str(value))

            try:
                #cal_result = float(eval(formula_replaced))
                cal_result = eval(formula_replaced)

            except ZeroDivisionError:
                raise Exception("Division by zero")

            config_alarms = items[i]['alarms']
            if 'warning' in config_alarms:
                bool_warning = eval(str(cal_result) + config_alarms['warning'])
                alarm_status_warning = handle_monitor_current(monitor_id, "warning", bool_warning)

            if 'alert' in config_alarms:
                bool_alert = eval(str(cal_result) + config_alarms['alert'])
                alarm_status_alert = handle_monitor_current(monitor_id, "alert", bool_alert)

            config_notify = items[i]['notify']
            send_notify = handle_notify(monitor_id, cal_result, config_alarms, config_notify, alarm_status_warning, alarm_status_alert)

            monitor_arr = {
                "monitor_id": monitor_id,
                "elk_env": elk_env,
                "elk_conn": elk_conn,
                "dict_log_count": dict_log_count,
                "formula": formula,
                "formula_replaced": formula_replaced,
                "cal_result": cal_result,
                "config_alarms": config_alarms,
                "bool_warning": str(bool_warning),
                "alarm_status_warning": alarm_status_warning,
                "bool_alert": str(bool_alert),
                "alarm_status_alert": alarm_status_alert,
                "send_notify": send_notify
            }
            return_list.append(monitor_arr)

    return return_list

#result = handler(None, None)
#print json.dumps(result)
