# -*- coding: utf-8 -*-
from __future__ import division
import json
import sys
import config
import re
import requests


valid_value_notify = ['slack']


def load_json_file(file_name):
    try:
        with open(file_name) as data_file:
            data = json.load(data_file)
    except ValueError:
        return False
    except IOError:
        return None
    else:
        return data


#result = load_json_file('sample.json')
#print result


def json_fields_check(json_arr):
    check_result = False
    missing_fields = []
    invalid_fields = []

    if 'monitor_id' not in json_arr:
        missing_fields.append('monitor_id')

    if 'enable' not in json_arr:
        missing_fields.append('enable')
    else:
        if json_arr['enable'] is not False:
            if json_arr['enable'] is not True:
                invalid_fields.append('enable')

    if 'formula' not in json_arr:
        missing_fields.append('formula')

    if 'parameters' not in json_arr:
        missing_fields.append('parameters')

    if 'notify' not in json_arr:
        missing_fields.append('notify')
    else:
        for item in json_arr['notify']:
            if item not in valid_value_notify:
                invalid_fields.append({"notify": item})

    if 'alarms' not in json_arr:
        missing_fields.append('alarms')
    else:
        if 'alert' not in json_arr['alarms']:
            if 'warning' not in json_arr['alarms']:
                missing_fields.append({"alarms": "alert"})
                missing_fields.append({"alarms": "warning"})

    if 'elk_env' not in json_arr:
        missing_fields.append('elk_env')
    else:
        if json_arr['elk_env'] != 'staging':
            if json_arr['elk_env'] != 'production':
                invalid_fields.append('elk_env')

    if len(missing_fields) == 0 and len(invalid_fields) == 0:
        check_result = True

    return_arr = {
        "check_result": check_result,
        "missing_fields":  missing_fields,
        "invalid_fields": invalid_fields
    }

    return return_arr


def get_log_dict_value(elk_conn, json_data, value_param):

    r = requests.post(elk_conn + "?size=0", data=json_data)
    json_res = json.loads(r.text)

    dict_list = value_param.split(".")

    str_key = ""
    for key in dict_list:
        str_key += '[\'' + key + '\']'

    return eval("json_res" + str_key)


def get_log_hit(elk_conn, json_data):
    r = requests.post(elk_conn, data=json_data)
    json_res = json.loads(r.text)
    return json_res['hits']['total']


'''
def formula_check(formula):
    try:
        cal_result = eval(formula_replaced + ".0")
        # print cal_result
    except ZeroDivisionError:
        # print "Division by zero"
        # raise Exception("Division by zero")
'''


def main(argv):
    if len(argv) == 2:
        file_name = argv[1]
        json_arr = load_json_file(file_name)
        if json_arr is None:
            return {"valid": False, "message": "[Error] File not found", "detail": ""}
        elif json_arr is False:
            return {"valid": False, "message": "[Error] Json parsing error", "detail": ""}
        else:
            json_check_arr = json_fields_check(json_arr)
            if json_check_arr['check_result']:
                # Get ELK endpoint from config
                elk_env = json_arr['elk_env']
                if elk_env == 'staging':
                    elk_conn = config.elk_stg
                elif elk_env == 'production':
                    elk_conn = config.elk_prod

                formula = json_arr['formula']

                # Replace ${} params
                pattern = re.compile(r'\$\{([A-Za-z0-9_.]+)\}')
                params = re.findall(pattern, formula)
                dict_log_count = {}
                for param in params:
                    param_log_count = get_log_hit(elk_conn, json.dumps(json_arr['parameters'][param]))
                    dict_log_count.update({"${" + param + "}": param_log_count})

                # Replace %{} params
                pattern_2 = re.compile(r'%\{([A-Za-z0-9_.]+)\}')
                params_2 = re.findall(pattern_2, formula)
                dict_log_value = {}
                for param in params_2:
                    param_log_value = get_log_dict_value(elk_conn, json.dumps(json_arr['parameters'][param]), param)
                    dict_log_value.update({"%{" + param + "}": param_log_value})

                # Replace formula for calculation
                formula_replaced = formula

                for key, value in dict_log_count.iteritems():
                    formula_replaced = formula_replaced.replace(key, str(value))

                for key, value in dict_log_value.iteritems():
                    formula_replaced = formula_replaced.replace(key, str(value))

                try:
                    #cal_result = float(eval(formula_replaced))
                    cal_result = eval(formula_replaced)

                    config_alarms = json_arr['alarms']
                    bool_warning = None
                    bool_alert = None
                    if 'warning' in config_alarms:
                        bool_warning = eval(str(cal_result) + config_alarms['warning'])

                    if 'alert' in config_alarms:
                        bool_alert = eval(str(cal_result) + config_alarms['alert'])

                    detail_arr = {
                        "cal_result": cal_result,
                        "dict_log_count": dict_log_count,
                        "config_alarms": config_alarms,
                        "bool_warning": bool_warning,
                        "bool_alert": bool_alert
                    }
                    return {"valid": True, "message": "OK", "detail": detail_arr}
                except ZeroDivisionError:
                    return {"valid": False, "message": "[ERROR] Division by zero", "detail": dict_log_count}

            else:
                return {"valid": False, "message": "[ERROR] json_fields_check failed", "detail": json_check_arr}
    else:
        return {"valid": False, "message": "[Error] Argument error", "detail": ""}

if __name__ == "__main__":
    # For Testing
    # sys.argv.append('sample3.json')

    result_arr = main(sys.argv)
    print result_arr


