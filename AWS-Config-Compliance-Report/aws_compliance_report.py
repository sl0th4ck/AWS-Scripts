import boto3
import csv
import json
from botocore.exceptions import ClientError
import pandas
from pandas import json_normalize
from datetime import date
from dateutil.tz import tzlocal
import datetime
import os.path
from os import path

#gets a list of all users for the AWS Account
def get_user_list(session_token):
    try:
        iam = session_token.client('iam')
        response = iam.list_users()
        return response
    except ClientError as e:
        print(e)

#takes a pandas dataframe and list of users.  Replaces the IAM User Id with the user name.
def userid_to_username(df, userlist):
    try:
        for column in df[['Resource Id']]:
            column_contents = df[column]
            for resource in column_contents:
                if resource.startswith('AIDA'):
                    for obj in userlist['Users']:
                        if obj['UserId'] == resource:
                            username = obj['UserName']
                            df = df.replace(to_replace=resource, value=username)

        return df
    except ClientError as e:
        print(e)

#returns a dict of all the rules.
def config_rules(session_token):
    try:
        config = session_token.client('config')
        paginator = config.get_paginator('describe_config_rules')
        pages = paginator.paginate()
        return pages
    except ClientError as e:
        print(e)

#retrieve the result of each rule from config.  This takes the session and rules.  This returns a pandas dataframe.
def config_results(session_token,rules):
    if path.exists('config_results.csv'):
        os.remove("config_results.csv")
    try:
        compliance_types = ['NON_COMPLIANT']
        config = session_token.client('config')
        df = pandas.DataFrame(columns=["Rule Name","Compliance","Resource Type","Resource Id", "Result Recorded Time"])
        for rule in rules:
            for obj in rule['ConfigRules']:

                rule_result = config.get_compliance_details_by_config_rule(
                ConfigRuleName=obj['ConfigRuleName'],
                ComplianceTypes=compliance_types
                )
                if rule_result['EvaluationResults']:
                    for obj2 in rule_result['EvaluationResults']:
                        rule_name = obj2['EvaluationResultIdentifier']['EvaluationResultQualifier']['ConfigRuleName']
                        compliance_type = obj2['ComplianceType']
                        resource_type = obj2['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']
                        resource_id =obj2['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                        result_recorded_time = obj2['ResultRecordedTime']
                        df = df.append({"Rule Name":rule_name,"Compliance":compliance_type,"Resource Type":resource_type,"Resource Id":resource_id, "Result Recorded Time":result_recorded_time },ignore_index=True)
        return df
    except ClientError as e:
        print(e)

def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

#get input from user concerning the profile and MFA.
aws_profile= input("AWS Profile: ")
aws_region = input("AWS Region: ")
serial_number = input("MFA Serial Number (ARN): ")
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

#get Rules
rules = config_rules(session)

#get results from rules as pandas dataframe
df = config_results(session, rules)

#get list of users for AWS Account
userlist = get_user_list(session)

#convert any IAM User Id's to Usernames.
df = userid_to_username(df, userlist)

#If old results exists, delete them.
if path.exists('config_results.csv'):
    os.remove("config_results.csv")
    
#Write pandas dataframe to CSV.
df.to_csv('config_results.csv')
