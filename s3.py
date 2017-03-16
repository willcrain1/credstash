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

from utils import *

import csv
import json
import operator
import sys
import boto3
import botocore.exceptions

@clean_fail
def createS3Credstash(region, bucket, **session_params):
	print("TODO: createS3Datastore method")

@clean_fail
def getAllS3Secrets(args, region, **session_params):
	print("TODO: getAllS3Keys method")

@clean_fail
def getS3SecretKey(args, region, **session_params):
	print("TODO: getS3SecretKey method")

@clean_fail
def putS3SecretKey(args, region, **session_params):
	print("TODO: putS3SecretKey method")

@clean_fail
def listS3Credstashes(region, args, **session_params):
	print("TODO: listS3Credstashes")

@clean fail
def deleteS3Secret(args.credential, region=region, bucket=args.bucket, **session_params):
	print("TODO: deleteS3Secret")