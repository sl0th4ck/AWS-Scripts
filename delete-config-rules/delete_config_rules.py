import boto3
import json
from botocore.exceptions import ClientError
import os.path

#gets a list of all config rules and returns a dict of each one.
def config_rules(session_token):
    try:
        config = session_token.client('config')
        paginator = config.get_paginator('describe_config_rules')
        pages = paginator.paginate()
        return pages
    except ClientError as e:
        print(e)

#retrieve the result of each rule from config.  This takes the session and rules.  This returns a dict of results.
def delete_rules(session_token,rules):
    try:
        config = session_token.client('config')

        for rule in rules:
            for obj in rule['ConfigRules']:
                config.delete_config_rule(
                    ConfigRuleName=obj['ConfigRuleName']
                )
                print("Deleted config rule %s" % obj['ConfigRuleName'])

    except ClientError as e:
        print(e)

#get input from user concerning the profile and MFA.
aws_profile= input("AWS Profile:  ")
aws_region = input("Region:  ")
serial_number = input("MFA Token Serial Number (ARN): ")
mfa_token = input("MFA Token: ")

#set the session so that it is using the correct profile
session = boto3.session.Session(profile_name=aws_profile)

#create the sts object from the session.
sts = session.client('sts')

#request a token using MFA
response = sts.get_session_token(
    DurationSeconds=900,
    SerialNumber=serial_number,
    TokenCode=mfa_token
)
#assign session token credentials to credentials dict.
credentials=response['Credentials']

#create session with MFA session token
session = boto3.session.Session(aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],region_name=aws_region)

#pull rules for profile
rules = config_rules(session)
delete_rules(session, rules)
