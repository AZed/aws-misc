#!/usr/bin/env python3
"""Duplicity S3 Automatic Lifecycle Manager

For a given bucket, find all Duplicity archive prefixes, and create
a lifecycle policy to migrate them to Glacier after a specified
number of days

Environment Variables
---------------------
To support Lambda configuration, most arguments can also be specified
as environment variables from the following list:

* DUPLICITY_PREFIX
* FILE_PREFIX_ARCHIVE
* BUCKET (but overridden if triggered by S3 event)
* CLEAN
* GLACIER_DAYS
* LIFECYCLE_ID_PREFIX
* NOOP

License and Copyright
---------------------
Copyright 2019 Zed Pobre <zed@resonant.org>

This code is licensed to the public under the terms of the GNU GPL,
version 2
"""

import argparse
import boto3
import re
import urllib.parse
import pprint

from os import environ as env
from distutils.util import strtobool

parser=argparse.ArgumentParser(
    description='Duplicity Automatic Lifecycle Manager'
)
parser.add_argument(
    '-p', '--duplicity-prefix',
    nargs='?',
    default=env.get('DUPLICITY_PREFIX','duplicity/'),
    help='Bucket prefix for all Duplicity backups'
)
parser.add_argument(
    '-a', '--file-prefix-archive',
    nargs='?',
    default=env.get('FILE_PREFIX_ARCHIVE','archive/'),
    help='Duplicity --file-prefix-archive value (final component in path)'
)
parser.add_argument(
    '-b','--bucket',
    nargs='?',
    default=env.get('BUCKET',None),
    help='AWS bucket to use (ignored in Lambda)'
)
parser.add_argument(
    '--clean',
    action='store_true',
    default=bool(strtobool(env.get('CLEAN','0'))),
    help="""Forcibly remove any existing rules on a prefix to be
    automatically managed, whether or not they were automatically
    created
    """
)
parser.add_argument(
    '-g', '--glacier_days',
    nargs='?',
    type=int,
    default=env.get('GLACIER_DAYS',60),
    help='Number of days before moving an archive to Glacier'
)
parser.add_argument(
    '--id','--lifecycle-id-prefix',
    dest='lifecycle_id_prefix',
    nargs='?',
    default=env.get('LIFECYCLE_ID_PREFIX','Duplicity-Auto-Lifecycle'),
    help='Prefix of the lifecycle rule ID (backup path will be appended)'
)
parser.add_argument(
    '--noop',
    action='store_true',
    default=bool(strtobool(env.get('NOOP','0'))),
    help="""Do not actually update any lifecycle rules.  Most useful
    in conjunction with verbose mode.
    """
)
parser.add_argument(
    '--profile',
    nargs='?',
    default=env.get('AWS_DEFAULT_PROFILE',None),
    help='AWS profile to use'
)
parser.add_argument(
    '-v','--verbose',
    action='store_true',
    default=bool(strtobool(env.get('VERBOSE','0'))),
    help='Print debugging output'
)
args=parser.parse_args()
if(args.verbose):
    print("Parameters:")
    for arg in vars(args):
        print("    {}={}".format(arg,getattr(args,arg)))


def archives_in_bucket(bucket,token=None):
    """Return a list of prefixes containing Duplicity archives

    Parameters
    ----------
    ### bucket
    Name of the S3 bucket to check

    ### token
    Continuation token (if any) used recursively to get around
    1000-value return limit
    """

    s3 = boto3.client('s3')

    try:
        if(token):
            objects = s3.list_objects_v2(
                Bucket=bucket,
                Prefix=args.duplicity_prefix,
                Delimiter=args.file_prefix_archive,
                ContinuationToken=token
            )
        else:
            if args.verbose:
                print('Searching for archive paths...')
            objects = s3.list_objects_v2(
                Bucket=bucket,
                Prefix=args.duplicity_prefix,
                Delimiter=args.file_prefix_archive,
            )

    except Exception as e:
        print(e)
        if(token):
            print('Error listing objects in bucket {} with token {}. Make sure it exists and is in the same region as this function.'.format(bucket,token))
        else:
            print('Error listing objects in bucket {}. Make sure it exists and is in the same region as this function.'.format(bucket))
        raise e

    prefixes=[]
    for plist in objects['CommonPrefixes']:
        prefixes.append(plist['Prefix'])
    if('NextContinuationToken' in objects):
        prefixes.append(archives_in_bucket(bucket,objects['NextContinuationToken']))
    return prefixes


def lambda_handler(event, context):
    """
    Amazon Lambda handler

    Event structure documented at:
    https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
    """

    bucket = event['Records'][0]['s3']['bucket']['name']
    # key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')

    archives = archives_in_bucket(bucket)
    lifecycle = lifecycle_update(bucket, archives)

    return lifecycle


def lifecycle_update(bucket, archives):
    """Update lifecycle rules for a set of archive prefixes

    This retrieves all existing lifecycle rules for the bucket,
    replaces all previous rules automatically generated with fresh
    ones created from the list of archive prefixes, and preserves any
    rules not automatically generated.

    A warning will be printed if a rule exists that specifically
    targets a Duplicity archive prefix, but does not have an ID
    indicating it was automatically generated.

    Parameters
    ----------
    ### bucket
    S3 bucket to update

    ### archives
    Array of prefixes pointing to Duplicity archives


    Returns
    -------
    The dict of rules used to update the lifecycle policy.
    """

    s3 = boto3.resource('s3')
    try:
        lifecycle = s3.BucketLifecycleConfiguration(bucket)
    except Exception as e:
        print(e)
        print('Error getting lifecycle config for bucket {}. Make sure it exists and is in the same region as this function.'.format(bucket))
        raise e

    newrules = []

    for rule in lifecycle.rules:
        match = re.match('{}(.*?)/{}'.format(args.duplicity_prefix,args.file_prefix_archive),
                         rule['Filter']['Prefix'])
        if(match):
            if(not rule['ID'].startswith(args.lifecycle_id_prefix)):
                if args.clean:
                    print('WARNING: discarding custom lifecycle rule for '+match.group(1)+'!')
                else:
                    print('WARNING: ignoring custom lifecycle rule for '+match.group(1)+'!')
                    newrules.append(rule)
        else:
            # Preserve unrelated rules without comment
            newrules.append(rule)

    for archive in archives:
        try:
            archive_name = re.match('{}(.*?)/{}'
                                    .format(args.duplicity_prefix,args.file_prefix_archive)
                                    ,archive).group(1)
        except Exception as e:
            print(e)
            print('Failed to parse previously parsed archive: {}',format(archive))
            raise e

        newrule = {
            'ID': args.lifecycle_id_prefix + '-' + archive_name,
            'Filter': {
                'Prefix': archive
            },
            'Status': 'Enabled',
            'Transitions': [
                { 'Days': args.glacier_days, 'StorageClass': 'GLACIER' }
            ]

        }
        newrules.append(newrule)

    try:
        if(not args.noop):
            lifecycle.put(LifecycleConfiguration=
                          { 'Rules': newrules }
            )
        else:
            print("Running in noop mode -- not updating lifecycle configuration")
    except Exception as e:
        print(e)
        print('Failed to update lifecycle rules:\n{}\n'.format(newrules))
        raise e

    return newrules


if(env.get('AWS_EXECUTION_ENV') is None):
    if(args.profile):
        boto3.setup_default_session(profile_name='backup')
    archives = archives_in_bucket(args.bucket)
    lifecycle = lifecycle_update(args.bucket, archives)
    if(args.verbose):
        print("Archives found:")
        for archive in archives:
            print("    "+archive)
        print("\nLifecycle rules:")
        pprint.pprint(lifecycle, indent=4)
