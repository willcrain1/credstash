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