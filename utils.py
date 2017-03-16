from __future__ import print_function

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


def printStdErr(s):
    sys.stderr.write(str(s))
    sys.stderr.write("\n")


def fatal(s):
    printStdErr(s)
    sys.exit(1)


def expand_wildcard(string, secrets):
    prog = re.compile('^' + string.replace(WILDCARD_CHAR, '.*') + '$')
    output = []
    for secret in secrets:
        if prog.search(secret) is not None:
            output.append(secret)
    return output


def csv_dump(dictionary):
    csvfile = StringIO()
    csvwriter = csv.writer(csvfile)
    for key in dictionary:
        csvwriter.writerow([key, dictionary[key]])
    return csvfile.getvalue()


def dotenv_dump(dictionary):
    dotenv_buffer = StringIO()
    for key in dictionary:
        dotenv_buffer.write("%s=%s\n" % (key.upper(), dictionary[key]))
    dotenv_buffer.seek(0)
    return dotenv_buffer.read()


def paddedInt(i):
    '''
    return a string that contains `i`, left-padded with 0's up to PAD_LEN digits
    '''
    i_str = str(i)
    pad = PAD_LEN - len(i_str)
    return (pad * "0") + i_str

