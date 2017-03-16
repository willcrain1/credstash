from __future__ import print_function
from utils import *

def clean_fail(func):
    '''
    A decorator to cleanly exit on a failed call to AWS.
    catch a `botocore.exceptions.ClientError` raised from an action.
    This sort of error is raised if you are targeting a region that
    isn't set up (see, `credstash setup`.
    '''
    def func_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
    return func_wrapper

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


def getHighestVersion(name, region=None, table="credential-store",
                      **kwargs):
    '''
    Return the highest version of `name` in the table
    '''
    session = get_session(**kwargs)

    dynamodb = session.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    response = secrets.query(Limit=1,
                             ScanIndexForward=False,
                             ConsistentRead=True,
                             KeyConditionExpression=boto3.dynamodb.conditions.Key(
                                 "name").eq(name),
                             ProjectionExpression="version")

    if response["Count"] == 0:
        return 0
    return response["Items"][0]["version"]





def listSecrets(region=None, table="credential-store", **kwargs):
    '''
    do a full-table scan of the credential-store,
    and return the names and versions of every credential
    '''
    session = get_session(**kwargs)

    dynamodb = session.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    response = secrets.scan(ProjectionExpression="#N, version",
                            ExpressionAttributeNames={"#N": "name"})
    return response["Items"]


def putSecret(name, secret, version="", kms_key="alias/credstash",
              region=None, table="credential-store", context=None,
              digest=DEFAULT_DIGEST, **kwargs):
    '''
    put a secret called `name` into the secret-store,
    protected by the key kms_key
    '''
    if not context:
        context = {}
    session = get_session(**kwargs)
    kms = session.client('kms', region_name=region)
    key_service = KeyService(kms, kms_key, context)
    sealed = seal_aes_ctr_legacy(
        key_service,
        secret,
        digest_method=digest,
    )

    dynamodb = session.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    data = {
        'name': name,
        'version': paddedInt(version),
    }
    data.update(sealed)

    return secrets.put_item(Item=data, ConditionExpression=Attr('name').not_exists())


def getAllSecrets(version="", region=None, table="credential-store",
                  context=None, credential=None, session=None, **kwargs):
    '''
    fetch and decrypt all secrets
    '''
    output = {}
    if session is None:
        session = get_session(**kwargs)
    dynamodb = session.resource('dynamodb', region_name=region)
    kms = session.client('kms', region_name=region)
    secrets = listSecrets(region, table, **kwargs)

    # Only return the secrets that match the pattern in `credential`
    # This already works out of the box with the CLI get action,
    # but that action doesn't support wildcards when using as library
    if credential and WILDCARD_CHAR in credential:
        names = set(expand_wildcard(credential,
                                    [x["name"]
                                     for x in secrets]))
    else:
        names = set(x["name"] for x in secrets)

    for credential in names:
        try:
            output[credential] = getSecret(credential,
                                           version,
                                           region,
                                           table,
                                           context,
                                           dynamodb,
                                           kms,
                                           **kwargs)
        except:
            pass
    return output


def getSecret(name, version="", region=None,
              table="credential-store", context=None,
              dynamodb=None, kms=None, **kwargs):
    '''
    fetch and decrypt the secret called `name`
    '''
    if not context:
        context = {}

    # Can we cache
    if dynamodb is None or kms is None:
        session = get_session(**kwargs)
        if dynamodb is None:
            dynamodb = session.resource('dynamodb', region_name=region)
        if kms is None:
            kms = session.client('kms', region_name=region)

    secrets = dynamodb.Table(table)

    if version == "":
        # do a consistent fetch of the credential with the highest version
        response = secrets.query(Limit=1,
                                 ScanIndexForward=False,
                                 ConsistentRead=True,
                                 KeyConditionExpression=boto3.dynamodb.conditions.Key("name").eq(name))
        if response["Count"] == 0:
            raise ItemNotFound("Item {'name': '%s'} couldn't be found." % name)
        material = response["Items"][0]
    else:
        response = secrets.get_item(Key={"name": name, "version": version})
        if "Item" not in response:
            raise ItemNotFound(
                "Item {'name': '%s', 'version': '%s'} couldn't be found." % (name, version))
        material = response["Item"]

    key_service = KeyService(kms, None, context)

    return open_aes_ctr_legacy(key_service, material)
