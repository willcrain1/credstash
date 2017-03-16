@clean_fail
def deleteSecrets(name, region=None, table="credential-store",
                  **kwargs):
    session = get_session(**kwargs)
    dynamodb = session.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    response = secrets.scan(FilterExpression=boto3.dynamodb.conditions.Attr("name").eq(name),
                            ProjectionExpression="#N, version",
                            ExpressionAttributeNames={"#N": "name"})

    for secret in response["Items"]:
        print("Deleting %s -- version %s" %
              (secret["name"], secret["version"]))
        secrets.delete_item(Key=secret)

@clean_fail
def list_credentials(region, args, **session_params):
    credential_list = listSecrets(region=region,
                                  table=args.table,
                                  **session_params)
    if credential_list:
        # print list of credential names and versions,
        # sorted by name and then by version
        max_len = max([len(x["name"]) for x in credential_list])
        for cred in sorted(credential_list,
                           key=operator.itemgetter("name", "version")):
            print("{0:{1}} -- version {2:>}".format(
                cred["name"], max_len, cred["version"]))
    else:
        return

@clean_fail
def putSecretAction(args, region, **session_params):
    if args.autoversion:
        latestVersion = getHighestVersion(args.credential,
                                          region,
                                          args.table,
                                          **session_params)
        try:
            version = paddedInt(int(latestVersion) + 1)
        except ValueError:
            fatal("Can not autoincrement version. The current "
                  "version: %s is not an int" % latestVersion)
    else:
        version = args.version
    try:
        if putSecret(args.credential, args.value, version,
                     kms_key=args.key, region=region, table=args.table,
                     context=args.context, digest=args.digest,
                     **session_params):
            print("{0} has been stored".format(args.credential))
    except KmsError as e:
        fatal(e)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            latestVersion = getHighestVersion(args.credential, region,
                                              args.table,
                                              **session_params)
            fatal("%s version %s is already in the credential store. "
                  "Use the -v flag to specify a new version" %
                  (args.credential, latestVersion))
        else:
            fatal(e)


@clean_fail
def getSecretAction(args, region, **session_params):
    try:
        if WILDCARD_CHAR in args.credential:
            names = expand_wildcard(args.credential,
                                    [x["name"]
                                     for x
                                     in listSecrets(region=region,
                                                    table=args.table,
                                                    **session_params)])
            print(json.dumps(dict((name,
                                   getSecret(name,
                                             args.version,
                                             region=region,
                                             table=args.table,
                                             context=args.context,
                                             **session_params))
                                  for name in names)))
        else:
            sys.stdout.write(getSecret(args.credential, args.version,
                                       region=region, table=args.table,
                                       context=args.context,
                                       **session_params))
            if not args.noline:
                sys.stdout.write("\n")
    except ItemNotFound as e:
        fatal(e)
    except KmsError as e:
        fatal(e)
    except IntegrityError as e:
        fatal(e)

@clean_fail
def getAllAction(args, region, **session_params):
    secrets = getAllSecrets(args.version,
                            region=region,
                            table=args.table,
                            context=args.context,
                            **session_params)
    if args.format == "json":
        output_func = json.dumps
        output_args = {"sort_keys": True,
                       "indent": 4,
                       "separators": (',', ': ')}
    elif not NO_YAML and args.format == "yaml":
        output_func = yaml.dump
        output_args = {"default_flow_style": False}
    elif args.format == 'csv':
        output_func = csv_dump
        output_args = {}
    elif args.format == 'dotenv':
        output_func = dotenv_dump
        output_args = {}
    print(output_func(secrets, **output_args))



@clean_fail
def createDdbTable(region=None, table="credential-store", **kwargs):
    '''
    create the secret store table in DDB in the specified region
    '''
    session = get_session(**kwargs)
    dynamodb = session.resource("dynamodb", region_name=region)
    if table in (t.name for t in dynamodb.tables.all()):
        print("Credential Store table already exists")
        return

    print("Creating table...")
    dynamodb.create_table(
        TableName=table,
        KeySchema=[
            {
                "AttributeName": "name",
                "KeyType": "HASH",
            },
            {
                "AttributeName": "version",
                "KeyType": "RANGE",
            }
        ],
        AttributeDefinitions=[
            {
                "AttributeName": "name",
                "AttributeType": "S",
            },
            {
                "AttributeName": "version",
                "AttributeType": "S",
            },
        ],
        ProvisionedThroughput={
            "ReadCapacityUnits": 1,
            "WriteCapacityUnits": 1,
        }
    )

    print("Waiting for table to be created...")
    client = session.client("dynamodb", region_name=region)
    client.get_waiter("table_exists").wait(TableName=table)

    print("Table has been created. "
          "Go read the README about how to create your KMS key")
