# AWS Lambda Elasticsearch LogMonitor
  Monitor specific log pattern/aggregations by Elasticsearch API. <br>
  Leverage AWS Lambda+DynamoDB to achieve serverless log monitoring solution.

## Introduction
  ElasticSearch provide [Search API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search.html), [Aggregations API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations) to query logs query/aggregations easily.  
  By leverage these API, we can create a monitoring method by aggragate specific log pattern volume/aggregations. And send notification.  
  In this project, we use Python to create AWS Lambda+DynamoDB to achieve serverless and flexible configuration log monitoring solution. (Lambda function create by [python-lambda](https://github.com/nficano/python-lambda))  
  
## Get Started
### Create Monitor Item
```
  1. Using HTTP request tool like Postman to valid your log filter patterns, the post body will be parameters we use later
  2. git clone
  3. Create monitor item json content (Please see paragraph "Monitor Item Parameter" or reference "/tools/sample.json")
  4. Use /tools/validation.py ${json_file} to valid the monitor item json content that you just created
  5. If validation passed, put this json content to DynamoDB table "lambda.elk.monitor"
```
  
### Monitor Item Parameter
Parameters              | Description                                                                                                                                          | Optional Value               | Example
----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- | ---------------
monitor_id              | The monitor name, will use for notification                                                                                                          | -                            | Cyclops-Beta-SignIn_FailedRate
enable                  | Whether enable this monitor or not                                                                                                                   | 1. true <br> 2. false        | true
elk_env                 | The elasticsearch environment to connect                                                                                                             | 1. staging <br>2. production | staging
formula                 | The formula for calculation, parameter: <br> 1. ${}:Log count (\$\{([A-Za-z0-9_.]+)\}) <br> 2. %{}:Json path with "." split (\%\{([A-Za-z0-9_.]+)\}) | -                            | 1. ${SignInFailed_Count}/${SignInTotal_Count} <br>2. %{aggregations.upstream_time.avg_value.value}
parameters              | The filter json content on Create Monitor Item - step1                                                                                               | -                            | -
alarms                  | The alarm criteria, will trigger by calculation result of formula                                                                                    | 1. alert <br>2. warning      | {"alert": ">=0.1","warning": ">=0.05"}
notify                  | The notification method                                                                                                                              | 1. slack                     | {"slack": "${SLACK_WebHook_URL}"}
  
