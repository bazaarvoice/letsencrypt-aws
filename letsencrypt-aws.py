import datetime
import json
import logging
import os
import argparse
import sys
import textwrap
import time

import acme.challenges
import acme.client
import acme.jose
import boto3
import botocore.exceptions
import dateutil.tz
import OpenSSL.crypto
import rfc3986

from collections import namedtuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from retry import retry


logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s',
                    level=logging.INFO)
logger = logging.getLogger('letsencrypt-aws')
logger.setLevel(logging.INFO)
# Boto3 logs private keys during upload, so disable its INFO logs
logging.getLogger('boto3').setLevel(logging.WARNING)

DEFAULT_ACME_DIRECTORY_URL = 'https://acme-v01.api.letsencrypt.org/directory'
STAGING_ACME_DIRECTORY_URL = \
    'https://acme-staging.api.letsencrypt.org/directory'
DEFAULT_ACME_PATH = '/acme/'
DEFAULT_EXPIRATION_THRESHOLD = 45
DNS_TTL = 30

today = datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())


def _get_expiring_certificates(iam,
                               path,
                               expiration_threshold):
    for cert in iam.server_certificates.filter(PathPrefix=path):
        renew_date = cert.server_certificate_metadata[
            'Expiration'] - expiration_threshold
        logger.info('Checking cert {}: Renew date: {} Now: {}'.format(
            cert.name, renew_date, today))
        if renew_date < today:
            yield cert


class ElbListener(object):

    def __init__(self, elb_client, elb_name, port):
        self.client = elb_client
        self.elb_name = elb_name
        self.port = port

    @retry(tries=5, delay=5, backoff=2)
    def update_cert(self, cert_arn):
        self.client.set_load_balancer_listener_ssl_certificate(
            LoadBalancerName=self.elb_name,
            LoadBalancerPort=self.port,
            SSLCertificateId=cert_arn)


def _get_elb_listeners_for_cert(elb_client, *cert_arns):
    for page in elb_client.get_paginator('describe_load_balancers').paginate():
        for elb in page['LoadBalancerDescriptions']:
            for description in elb['ListenerDescriptions']:
                listener = description['Listener']
                ssl_cert_arn = listener.get('SSLCertificateId')
                if ssl_cert_arn in cert_arns:
                    yield ElbListener(elb_client,
                                      elb['LoadBalancerName'],
                                      listener['LoadBalancerPort'])


def _change_elb_cert(old_cert, new_cert, regions):
    elb_clients = {region: boto3.client(
        'elb', region_name=region) for region in regions}
    old_arn = _get_cert_arn(old_cert)
    new_arn = _get_cert_arn(new_cert)
    for region in regions:
        # Sometimes the API takes a bit to catch up,
        # so look for ELBs with either ARN
        for elb_listener in _get_elb_listeners_for_cert(elb_clients[region],
                                                        old_arn,
                                                        new_arn):
            logger.info('Updating elb: {} with cert: {}'.format(
                elb_listener.elb_name, new_arn))
            elb_listener.update_cert(new_arn)


def _get_domains_for_cert(cert_body):
    cert = x509.load_pem_x509_certificate(cert_body, default_backend())
    try:
        san_extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        # Handle the case where an old certificate doesn't have a SAN
        domains = [name.value for name in cert.subject]
    else:
        domains = san_extension.value.get_values_for_type(
            x509.DNSName
        )
    return domains


Certificate = namedtuple('Certificate', ['name', 'key', 'cert_body', 'chain'])


def _provision_cert(name, hosts, acme_client, dns_challenge_completer):
    private_key = generate_rsa_private_key()
    csr = generate_csr(private_key, hosts)

    authorizations = []
    try:
        for host in hosts:
            authz_record = start_dns_challenge(
                acme_client, dns_challenge_completer,
                host,
            )
            authorizations.append(authz_record)

        for authz_record in authorizations:
            complete_dns_challenge(
                acme_client, dns_challenge_completer,
                authz_record
            )

        logger.info('Requesting {} cert'.format(name))
        pem_certificate, pem_certificate_chain = request_certificate(
            acme_client, authorizations, csr
        )

    finally:
        for authz_record in authorizations:
            logger.info('Deleting {} txt records'.format(authz_record.host))
            dns_challenge = authz_record.dns_challenge
            dns_challenge_completer.delete_txt_record(
                authz_record.change_id,
                dns_challenge.validation_domain_name(authz_record.host),
                dns_challenge.validation(acme_client.key),
            )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    return Certificate(name,
                       private_key_bytes,
                       pem_certificate,
                       pem_certificate_chain)


def _upload_cert(cert, iam, path='/'):
    return iam.create_server_certificate(
        Path=path,
        ServerCertificateName=cert.name,
        CertificateBody=cert.cert_body,
        PrivateKey=cert.key,
        CertificateChain=cert.chain
    )


def _get_cert_arn(cert):
    return cert.server_certificate_metadata['Arn']


def _write_cert(cert):
    with open(cert.name + '.key', 'w') as key:
        key.write(cert.key)
    with open(cert.name + '.crt', 'w') as crt:
        crt.write(cert.cert_body)
    with open(cert.name + '.chain', 'w') as chain:
        chain.write(cert.chain)


def _read_cert_from_disk(name):
    with open(name + '.key') as key:
        private_key = key.read()
    with open(name + '.crt') as crt:
        cert_body = crt.read()
    with open(name + '.chain') as chain:
        cert_chain = chain.read()
    return Certificate(name, private_key, cert_body, cert_chain)


def create(acme_client,
           route53_client,
           hosts,
           path,
           name,
           save_local_copy=False):
    iam = boto3.resource('iam')
    challenge_completer = Route53ChallengeCompleter(route53_client)
    logger.info('Creating certificate: {}'.format(name))
    new_cert = _provision_cert(
        name, hosts, acme_client, challenge_completer)
    if(save_local_copy):
        logger.info('Saving certificate {} to disk'.format(name))
        _write_cert(new_cert)
    logger.info('Uploading new {} certificate'.format(name))
    _upload_cert(new_cert, iam, path)


def update(acme_client,
           route53_client,
           path,
           expiration_threshold,
           regions,
           read_local_copy=False,
           save_local_copy=False):
    iam = boto3.resource('iam')
    challenge_completer = Route53ChallengeCompleter(route53_client)
    for cert in _get_expiring_certificates(iam, path, expiration_threshold):
        if read_local_copy:
            logger.info('Reading cert {} from disk'.format(cert.name))
            new_cert = _read_cert_from_disk(cert.name)
        else:
            logger.info('Renewing certificate: {}'.format(cert.name))
            hosts = _get_domains_for_cert(cert.certificate_body)
            new_cert = _provision_cert(
                cert.name, hosts, acme_client, challenge_completer)
        if(save_local_copy):
            logger.info('Saving certificate {} to disk'.format(cert.name))
            _write_cert(new_cert)
        logger.info('Renaming {} certificate'.format(cert.name))
        old_cert = cert.update(NewServerCertificateName=cert.name + '-old')
        logger.info('Uploading renewed {} certificate'.format(cert.name))
        renewed_cert = _upload_cert(new_cert, iam, path)
        logger.info('Finding ELBs with cert {}'.format(old_cert))
        _change_elb_cert(old_cert, renewed_cert, regions)
        logger.info('Deleting old certificate: {}'.format(old_cert.name))
        old_cert.delete()
        logger.info('Done renewing certificate: {}'.format(cert.name))


class Route53ChallengeCompleter(object):

    def __init__(self, route53_client):
        self.route53_client = route53_client

    def _find_zone_id_for_domain(self, domain):
        paginator = self.route53_client.get_paginator('list_hosted_zones')
        zones = []
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                subdomain = '.' + zone['Name']
                if (
                    domain.endswith(subdomain) or
                    (domain + '.').endswith(subdomain)
                ) and not zone['Config']['PrivateZone']:
                    zones.append((zone['Name'], zone['Id']))

        if not zones:
            raise ValueError(
                'Unable to find a Route53 hosted zone for {}'.format(domain)
            )

        # Order the zones that are suffixes for our desired to domain by
        # length, this puts them in an order like:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        # And then we choose the last one, which will be the most specific.
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _change_txt_record(self, action, zone_id, domain, value):
        response = self.route53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': action,
                        'ResourceRecordSet': {
                            'Name': domain,
                            'Type': 'TXT',
                            'TTL': DNS_TTL,
                            'ResourceRecords': [
                                # For some reason TXT records need to be
                                # manually quoted.
                                {'Value': '"{}"'.format(value)}
                            ],
                        }
                    }
                ]
            }
        )
        return response['ChangeInfo']['Id']

    def create_txt_record(self, host, value):
        zone_id = self._find_zone_id_for_domain(host)
        change_id = self._change_txt_record(
            'CREATE',
            zone_id,
            host,
            value,
        )
        return (zone_id, change_id)

    def delete_txt_record(self, change_id, host, value):
        zone_id, _ = change_id
        self._change_txt_record(
            'DELETE',
            zone_id,
            host,
            value
        )

    def wait_for_change(self, change_id):
        _, change_id = change_id

        while True:
            response = self.route53_client.get_change(Id=change_id)
            if response['ChangeInfo']['Status'] == 'INSYNC':
                return
            time.sleep(5)


def generate_rsa_private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def generate_ecdsa_private_key():
    return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())


def generate_csr(private_key, hosts):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        # This is the same thing the official letsencrypt client does.
        x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, hosts[0]),
        ])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(host)
            for host in hosts
        ]),
        # TODO: change to `critical=True` when Let's Encrypt supports it.
        critical=False,
    )
    return csr_builder.sign(private_key, hashes.SHA256(), default_backend())


def find_dns_challenge(authz):
    for combo in authz.body.resolved_combinations:
        if (
            len(combo) == 1 and
            isinstance(combo[0].chall, acme.challenges.DNS01)
        ):
            yield combo[0]


def generate_certificate_name(hosts, cert):
    return '{serial}-{expiration}-{hosts}'.format(
        serial=cert.serial,
        expiration=cert.not_valid_after.date(),
        hosts='-'.join(h.replace('.', '_') for h in hosts),
    )[:128]


class AuthorizationRecord(object):

    def __init__(self, host, authz, dns_challenge, change_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.change_id = change_id


def start_dns_challenge(acme_client, dns_challenge_completer, host):
    logger.info('Start {} DNS challenge'.format(host))
    authz = acme_client.request_domain_challenges(
        host, acme_client.directory.new_authz
    )

    [dns_challenge] = find_dns_challenge(authz)

    logger.info('Creating TXT record for {}'.format(host))
    change_id = dns_challenge_completer.create_txt_record(
        dns_challenge.validation_domain_name(host),
        dns_challenge.validation(acme_client.key),

    )
    return AuthorizationRecord(
        host,
        authz,
        dns_challenge,
        change_id,
    )


def complete_dns_challenge(acme_client, dns_challenge_completer,
                           authz_record):
    dns_challenge_completer.wait_for_change(authz_record.change_id)

    response = authz_record.dns_challenge.response(acme_client.key)

    logger.info('Validating {} challenge'.format(authz_record.host))
    verified = response.simple_verify(
        authz_record.dns_challenge.chall,
        authz_record.host,
        acme_client.key.public_key()
    )
    if not verified:
        raise ValueError('Failed verification')

    logger.info('Answering {} challenge'.format(authz_record.host))
    acme_client.answer_challenge(authz_record.dns_challenge, response)


def request_certificate(acme_client, authorizations, csr):
    cert_response, _ = acme_client.poll_and_request_issuance(
        acme.jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1,
                csr.public_bytes(serialization.Encoding.DER),
            )
        ),
        authzrs=[authz_record.authz for authz_record in authorizations],
    )
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    )
    pem_certificate_chain = b"\n".join(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for cert in acme_client.fetch_chain(cert_response)
    )
    return pem_certificate, pem_certificate_chain


def setup_acme_client(s3_client, acme_directory_url, acme_account_key):
    uri = rfc3986.urlparse(acme_account_key)
    if uri.scheme == 'file' or uri.scheme is None:
        if uri.host is None:
            path = uri.path
        elif uri.path is None:
            path = uri.host
        else:
            path = os.path.join(uri.host, uri.path)
        with open(path) as f:
            key = f.read()
    elif uri.scheme == 's3':
        # uri.path includes a leading "/"
        response = s3_client.get_object(Bucket=uri.host, Key=uri.path[1:])
        key = response['Body'].read()
    else:
        raise ValueError(
            'Invalid acme account key: {!r}'.format(acme_account_key)
        )

    key = serialization.load_pem_private_key(
        key.encode("utf-8"), password=None, backend=default_backend()
    )
    return acme_client_for_private_key(acme_directory_url, key)


def acme_client_for_private_key(acme_directory_url, private_key):
    return acme.client.Client(
        # TODO: support EC keys, when acme.jose does.
        acme_directory_url, key=acme.jose.JWKRSA(key=private_key)
    )


def register(email, out, acme_directory_url=DEFAULT_ACME_DIRECTORY_URL):
    logger.info('acme-register.generate-key')
    private_key = generate_rsa_private_key()
    acme_client = acme_client_for_private_key(acme_directory_url, private_key)

    logger.info('acme-register.register')
    registration = acme_client.register(
        acme.messages.NewRegistration.from_data(email=email)
    )
    logger.info('acme-register.agree-to-tos')
    acme_client.agree_to_tos(registration)
    out.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def build_register_parser(parser):
    parser.add_argument(
        '--email',
        required=True,
        help="e-mail address to register Let's Encrypt account for.",
    )
    parser.add_argument(
        '--out',
        help='File to write the new private key to. Default: - (stdout)',
        type=argparse.FileType('w'),
        default='-',
    )
    add_acme_url_args(parser)
    parser.set_defaults(
        func=lambda args: register(args.email, args.key, args.acme_url))


def build_create_parser(parser):
    add_cert_args(parser)
    parser.add_argument(
        '--domains',
        nargs='+',
        required=True,
        help='Domains to include in the cert.'
    )
    parser.add_argument(
        '--name',
        help=textwrap.dedent('''
            Name for uploaded cert.
            Default: First domain specified, with dashes in place of dots.
            '''),
    )

    def create_command(args):
        s3_client = boto3.client('s3')
        acme_client = setup_acme_client(s3_client, args.acme_url, args.key)
        route53_session = boto3.session.Session(
            profile_name=args.route53_profile)
        route53_client = route53_session.client('route53')
        create(acme_client=acme_client,
               route53_client=route53_client,
               hosts=args.domains,
               path=args.path,
               name=args.name or args.domains[0].replace('.', '-'),
               save_local_copy=args.save_local_certs,
               )
    parser.set_defaults(func=create_command)


def build_update_parser(parser):
    add_cert_args(parser)
    parser.add_argument(
        '--expiration-threshold',
        help=textwrap.dedent('''
            How many days from expiration to replace certs.
            Default: %(default)s
            '''),
        default=DEFAULT_EXPIRATION_THRESHOLD,
    )
    parser.add_argument(
        '--regions',
        nargs='*',
        help='Regions to update ELBs in.',
        default=['us-east-1', 'us-west-2', 'eu-west-1'],
    )
    parser.add_argument(
        '--local-certs',
        action='store_true',
        help=textwrap.dedent('''
            Read certs from disk rather than provisioning new ones.
            Useful when reusing certs from a previous --save-local-certs run.
            Certs should be in the working directory with filenames like
            ${name}.{key,crt,chain}
            '''),
    )

    def update_command(args):
        s3_client = boto3.client('s3')
        acme_client = setup_acme_client(s3_client, args.acme_url, args.key)
        route53_session = boto3.session.Session(
            profile_name=args.route53_profile)
        route53_client = route53_session.client('route53')
        update(acme_client=acme_client,
               route53_client=route53_client,
               path=args.path,
               expiration_threshold=datetime.timedelta(
                   days=args.expiration_threshold),
               regions=args.regions,
               read_local_copy=args.use_local_certs,
               save_local_copy=args.save_local_certs,
               )
    parser.set_defaults(func=update_command)


def add_acme_url_args(parser):
    url_group = parser.add_mutually_exclusive_group()
    url_group.add_argument(
        '--acme-url',
        help='ACME directory URL. Default: %(default)s',
        default=DEFAULT_ACME_DIRECTORY_URL,
    )
    url_group.add_argument(
        '--staging',
        dest='acme_url',
        action='store_const',
        const=STAGING_ACME_DIRECTORY_URL,
        help=textwrap.dedent('''
            Use the Let's Encrypt staging API.
            Only do this for testing, not with live certs.
            ''')
        )


def add_cert_args(parser):
    parser.add_argument(
        '--key',
        required=True,
        help="Let's Encrypt account key. Can be a local file or S3 URL.",
    )
    parser.add_argument(
        '--path',
        help="IAM path for Let's Encrypt certs. Default: %(default)s",
        default=DEFAULT_ACME_PATH,
    )
    parser.add_argument(
        '--route53-profile',
        help='AWS profile to use for Route53 actions.',
    )
    parser.add_argument(
        '--save-local-certs',
        action='store_true',
        help=textwrap.dedent('''
            Save a copy of new certs to disk.
            Files will be named ${name}.{key,crt,chain}
            '''),
    )
    add_acme_url_args(parser)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    register_parser = subparsers.add_parser(
        'register',
        description="Register a Let's Encrypt account",
    )
    build_register_parser(register_parser)
    create_parser = subparsers.add_parser(
        'create',
        description="Create a new cert and upload it to IAM."
    )
    build_create_parser(create_parser)
    update_parser = subparsers.add_parser(
        'update',
        description='Update certs that will expire soon.',
    )
    build_update_parser(update_parser)
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
