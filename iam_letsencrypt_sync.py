#!/usr/bin/env python3
"""IAM LetsEncrypt Synchronizer

On a system that is already configured to automatically renew
LetsEncrypt certificates, running this script will synchronize those
certificates into AWS IAM as server certificates.

License and Copyright
---------------------
Copyright 2019 Zed Pobre <zed@resonant.org>

This code is licensed to the public under the terms of the GNU GPL,
version 2
"""

import argparse
import boto3
import pprint

from datetime import datetime, timedelta, timezone
from distutils.util import strtobool
from os import environ as env
from os import scandir
from os.path import isdir, isfile

parser = argparse.ArgumentParser(
    description='IAM LetsEncrypt Synchronizer'
)
parser.add_argument(
    '--days','-d',
    nargs='?',
    default=30,
    type=int,
    help='Number of days to expiration when certificate replacement will happen automatically'
)
parser.add_argument(
    '--force','-f',
    action='store_true',
    default=False,
    help="""Overwrite any existing certificates, even if they are not
    close to expiration"""
)
parser.add_argument(
    '--livepath',
    nargs='?',
    default='/etc/letsencrypt/live',
    help="""The filesystem path where the LetsEncrypt live certificates can
    be found.  Defaults to '/etc/letsencrypt/live'"""
)
parser.add_argument(
    '-p', '--path',
    nargs='?',
    default='/cloudfront/',
    help="""The IAM path for the server certificate.  To ensure compatibility
    with Amazon CloudFront distributions, the default value for this is set
    to '/cloudfront/'"""
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
args = parser.parse_args()
if(args.verbose):
    print("Parameters:")
    for arg in vars(args):
        print("    {}={}".format(arg,getattr(args,arg)))
if(args.profile):
        boto3.setup_default_session(profile_name=args.profile)


def certificate_expirations(marker=None):
    """Return a dictionary mapping certificate names to certificate expiration dates"""

    iam = boto3.client('iam')
    certlist = []
    expires = {}

    try:
        if(marker):
            response = iam.list_server_certificates(
                PathPrefix=args.path,
                Marker=marker
            )
        else:
            response = iam.list_server_certificates(
                PathPrefix=args.path
            )
    except Exception as e:
        print(e)
        if(marker):
            print('Error listing server certificates with path {}, starting with marker {}.'.format(args.path,marker))
        else:
            print('Error listing server certificates with path {}'.format(args.path))
        raise e

    for certdata in response['ServerCertificateMetadataList']:
        expires[certdata['ServerCertificateName']] = certdata['Expiration']
    if('Marker' in response):
        expires = dictmerge(expires,list_certificates(Marker=response['Marker']))

    return expires

def dictmerge(x,y):
    """Merge two dictionaries (to support Python < 3.5)"""
    z = x.copy()
    z.update(y)
    return z

def iam_delete_cert(name):
    """Delete an IAM server certificate"""

    iam = boto3.client('iam')

    try:
        if args.verbose:
            print("DEBUG: deleting server certificate: {}".format(name))
        iam.delete_server_certificate(ServerCertificateName=name)
    except Exception as e:
        print('Failed to delete IAM certificate {}'.format(name))
        print(e)
        raise e

def iam_sync_certs():
    """Synchronize LetsEncrypt certificates to IAM

    For each valid certificate set in the LetsEncrypt live directory,
    checks to see if a matching IAM certificate exists.  If it does,
    and it is close to its expiration date (or --force is specified),
    it will be deleted before uploading a new cert.
    """

    certnames = letsencrypt_certnames(args.livepath)
    expires = certificate_expirations()
    for certname in certnames:
        if(args.verbose):
            print("DEBUG: Checking {} for synchronization".format(certname))
        if certname in expires.keys():
            replacedate = expires[certname] - timedelta(days=args.days)
            if(datetime.now(timezone.utc) >= replacedate):
                if(args.verbose):
                    print("Replacing {} because it is expiring in less than {} days (at risk after {})"
                          .format(certname, args.days, replacedate.strftime('%Y-%m-%d')))
                iam_delete_cert(certname)
                iam_upload_cert(certname)
            elif(args.force):
                if(args.verbose):
                    print("Forcing replacement of {}")
                iam_delete_cert(certname)
                iam_upload_cert(certname)
            else:
                if(args.verbose):
                    print("Ignoring existing cert for {} (not at risk until {})"
                          .format(certname,replacedate.strftime('%Y-%m-%d')))
        else:
            # No certificate of that name at all, just upload
            iam_upload_cert(certname)


def iam_upload_cert(name):
    """Upload a LetsEncrypt certificate to IAM"""

    iam = boto3.client('iam')

    try:
        if(args.verbose):
            print("DEBUG: uploading server certificate {}{}".format(args.path,name))
        iam.upload_server_certificate(
            Path=args.path,
            ServerCertificateName=name,
            CertificateBody=letsencrypt_cert(name),
            PrivateKey=letsencrypt_privkey(name),
            CertificateChain=letsencrypt_chain(name)
        )
    except Exception as e:
        print('Failed to upload IAM certificate {}'.format(name))
        print(e)
        raise e

def letsencrypt_cert(name, livepath=args.livepath):
    """Return the text of a LetsEncrypt certificate"""

    filename = livepath + "/" + name + "/cert.pem"
    try:
        fh = open(filename)
        text = fh.read()
    except Exception as e:
        print('Failed to read LetsEncrypt certificate {} '.format(filename))
        print(e)
        raise e

    return text

def letsencrypt_certnames(livepath=args.livepath):
    """Return a list of live LetsEncrypt certificates"""

    valid = []
    for candidate in scandir(livepath):
        if(isdir(candidate)):
            if(isfile(livepath + "/" + candidate.name + "/cert.pem")
               and isfile(livepath + "/" + candidate.name + "/chain.pem")
               and isfile(livepath + "/" + candidate.name + "/privkey.pem")
            ):
                valid.append(candidate.name)
            else:
                print("WARNING: certificate data not found in {}".format(livepath + "/" + candidate.name))

    return valid

def letsencrypt_chain(name, livepath=args.livepath):
    """Return the text of a LetsEncrypt chain file"""

    filename = livepath + "/" + name + "/chain.pem"
    try:
        fh = open(filename)
        text = fh.read()
    except Exception as e:
        print('Failed to read LetsEncrypt chain file {} '.format(filename))
        print(e)
        raise e

    return text

def letsencrypt_privkey(name, livepath=args.livepath):
    """Return the text of a LetsEncrypt private key"""

    filename = livepath + "/" + name + "/privkey.pem"
    try:
        fh = open(filename)
        text = fh.read()
    except Exception as e:
        print('Failed to read LetsEncrypt private key {} '.format(filename))
        print(e)
        raise e

    return text


### Entry Point ###

iam_sync_certs()
