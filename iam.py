#!/usr/bin/env python
# Copyright 2015 Luminal, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import boto3

def get_session_params(profile, arn):
    params = {}
    if profile is None and arn:
        params = get_assumerole_credentials(arn)
    elif profile:
        params = dict(profile_name=profile)
    return params
    

def get_session(aws_access_key_id=None, aws_secret_access_key=None,
                aws_session_token=None, profile_name=None):
    if get_session._cached_session is None:
        get_session._cached_session = boto3.Session(aws_access_key_id=aws_access_key_id,
                                                    aws_secret_access_key=aws_secret_access_key,
                                                    aws_session_token=aws_session_token,
                                                    profile_name=profile_name)
    return get_session._cached_session
get_session._cached_session = None


def get_assumerole_credentials(arn):
    sts_client = boto3.client('sts')
    # Use client object and pass the role ARN
    assumedRoleObject = sts_client.assume_role(RoleArn=arn,
                                               RoleSessionName="AssumeRoleCredstashSession1")
    credentials = assumedRoleObject['Credentials']
    return dict(aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'])