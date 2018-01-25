aws_access_key_id = '${AWS_ACCESS_KEY_ID}'
aws_secret_access_key = '${AWS_SECRET_ACCESS_KEY}'
aws_region = '${AWS_REGION}'
#Create the dynamo_db table below
table_name_config = 'lambda.elk.monitor'
table_name_current = 'lambda.elk.monitor.current'
elk_stg = 'https://${ELK_PROD_FQDN}/_search'
elk_prod = 'https://${ELK_STAG_FQDN}/_search'