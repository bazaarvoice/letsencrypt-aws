**NOTE:** This is Bazaarvoice's fork of `letsencrypt-aws`. While it performs
basically the same job as the original, its usage is very different. The
main changes are:

1. Configuration is done via command line arguments instead of an environment
   variable containing JSON.
2. Certificates and ELBs are discovered via AWS APIs, instead of specified in
   configuration.
3. Persistent execution is no longer supported. Instead, it is designed to
   be run on a schedule (for example in Lambda with a CloudWatch Events
   Scheduled Rule).

# letsencrypt-aws

`letsencrypt-aws` is a script that can automatically update certificates
on your AWS infrastructure using the AWS APIs and Let's Encrypt.

## How it works

`letsencrypt-aws` looks for certificates that are going to expire soon
(in less than 45 days by default). For each expiring certificate, it
generates a new private key and CSR and sends a request to Let's Encrypt.
It takes the DNS challenge and creates a record in Route53 for that challenge.
This completes the challenge and, so Let's Encrypt provides a certificate.
The old certificate in IAM is renamed, and the new certificate and private key
is uploaded. Any ELBs using the certificate are updated to make sure they use
the new one.

So all you need to do is make sure this is running regularly, and your
ELBs' certificates will be kept minty fresh.

## Getting started

Before you can use `letsencrypt-aws` you need to have created an account with
the ACME server (you only need to do this the first time). You can register
using the `register` subcommand:

```console
$ # If you're trying to register for a server besides the Let's Encrypt
$ # production one, use the --acme-url option
$ python letsencrypt-aws.py register --email email@example.com --out letsencrypt.pem
2016-01-09 19:56:19,123 INFO [acme-register.generate-key]
2016-01-09 19:56:20,456 INFO [acme-register.register]
2016-01-09 19:56:21,789 INFO [acme-register.agree-to-tos]
```

You'll need to put the private key somewhere that `letsencrypt-aws` can access
it (either on the local filesystem or in S3). The above example stored the
key locally in a file named `letsencrypt.pem`.

You will also need to have your AWS credentials configured. You can use any of
the [mechanisms documented by
boto3](https://boto3.readthedocs.io/en/latest/guide/configuration.html), or
use IAM instance profiles (which are supported, but not mentioned by the
`boto3` documentation). See [IAM Policy](#iam-policy) for which AWS permissions
are required.


## Creating a new cert

Once you have an account, you can create new certificates with the `create`
subcommand:

```console
$ python letsencrypt-aws.py --key letsencrypt.pem --domains example.com
2016-12-14 13:56:07,456 INFO Creating certificate: example-com
2016-12-14 13:56:08,103 INFO Start example.com DNS challenge
2016-12-14 13:56:08,216 INFO Creating TXT record for example.com
2016-12-14 13:56:44,255 INFO Validating example.com challenge
2016-12-14 13:56:44,315 INFO Answering example.com challenge
2016-12-14 13:56:46,543 INFO Requesting example-com cert
2016-12-14 13:56:47,628 INFO Deleting example.com txt records
2016-12-14 13:56:48,789 INFO Uploading new example-com certificate
```

## Updating expiring certs

With a cert created and in use, you'll want to keep it up to date.
This can be done by running the `update` command regularly.

```console
$ python letsencrypt-aws.py update --key lets-encrypt.pem
2016-12-14 14:40:52,865 INFO Checking cert example-com: Renew date: 2016-11-14 19:13:00+00:00 Now: 2016-12-14 20:40:51.385013+00:00
2016-12-14 14:40:53,456 INFO Renewing certificate: example-com
2016-12-14 14:40:54,103 INFO Start example.com DNS challenge
2016-12-14 14:40:54,216 INFO Creating TXT record for example.com
2016-12-14 14:41:44,255 INFO Validating example.com challenge
2016-12-14 14:41:44,315 INFO Answering example.com challenge
2016-12-14 14:41:46,543 INFO Requesting example-com cert
2016-12-14 14:41:47,628 INFO Deleting example.com txt records
2016-12-14 14:41:48,776 INFO Renaming example-com certificate
2016-12-14 14:41:48,964 INFO Uploading renewed example-com certificate
2016-12-14 14:41:53,156 INFO Finding ELBs with cert iam.ServerCertificate(name='example-com')
2016-12-14 14:42:00,526 INFO Updating elb: example-elb with cert: arn:aws:iam::123456789012:server-certificate/acme/example-com
2016-12-14 14:42:19,920 INFO Deleting old certificate: example-com
```

## Full usage

### Register
```console
$ python letsencrypt-aws.py register --help
usage: letsencrypt-aws.py register [-h] --email EMAIL [--out OUT]
                                   [--acme-url ACME_URL | --staging]

Register a Let's Encrypt account

optional arguments:
  -h, --help           show this help message and exit
  --email EMAIL        e-mail address to register Let's Encrypt account for.
  --out OUT            File to write the new private key to. Default: -
                       (stdout)
  --acme-url ACME_URL  ACME directory URL. Default:
                       https://acme-v01.api.letsencrypt.org/directory
  --staging            Use the Let's Encrypt staging API. Only do this for
                       testing, not with live certs.
```

### Create
```console
$ python letsencrypt-aws.py create --help
usage: letsencrypt-aws.py create [-h] --key KEY [--path PATH]
                                 [--route53-profile ROUTE53_PROFILE]
                                 [--save-local-certs]
                                 [--acme-url ACME_URL | --staging] --domains
                                 DOMAINS [DOMAINS ...] [--name NAME]

Create a new cert and upload it to IAM.

optional arguments:
  -h, --help            show this help message and exit
  --key KEY             Let's Encrypt account key. Can be a local file or S3
                        URL.
  --path PATH           IAM path for Let's Encrypt certs. Default: /acme/
  --route53-profile ROUTE53_PROFILE
                        AWS profile to use for Route53 actions.
  --save-local-certs    Save a copy of new certs to disk. Files will be named
                        ${name}.{key,crt,chain}
  --acme-url ACME_URL   ACME directory URL. Default:
                        https://acme-v01.api.letsencrypt.org/directory
  --staging             Use the Let's Encrypt staging API. Only do this for
                        testing, not with live certs.
  --domains DOMAINS [DOMAINS ...]
                        Domains to include in the cert.
  --name NAME           Name for uploaded cert. Default: First domain
                        specified, with dashes in place of dots.
```

### Update
```console
$ python letsencrypt-aws.py update --help
usage: letsencrypt-aws.py update [-h] --key KEY [--path PATH]
                                 [--route53-profile ROUTE53_PROFILE]
                                 [--save-local-certs]
                                 [--acme-url ACME_URL | --staging]
                                 [--expiration-threshold EXPIRATION_THRESHOLD]
                                 [--regions [REGIONS [REGIONS ...]]]
                                 [--local-certs]

Update certs that will expire soon.

optional arguments:
  -h, --help            show this help message and exit
  --key KEY             Let's Encrypt account key. Can be a local file or S3
                        URL.
  --path PATH           IAM path for Let's Encrypt certs. Default: /acme/
  --route53-profile ROUTE53_PROFILE
                        AWS profile to use for Route53 actions.
  --save-local-certs    Save a copy of new certs to disk. Files will be named
                        ${name}.{key,crt,chain}
  --acme-url ACME_URL   ACME directory URL. Default:
                        https://acme-v01.api.letsencrypt.org/directory
  --staging             Use the Let's Encrypt staging API. Only do this for
                        testing, not with live certs.
  --expiration-threshold EXPIRATION_THRESHOLD
                        How many days from expiration to replace certs.
                        Default: 45
  --regions [REGIONS [REGIONS ...]]
                        Regions to update ELBs in.
  --local-certs         Read certs from disk rather than provisioning new
                        ones. Useful when reusing certs from a previous
                        --save-local-certs run. Certs should be in the working
                        directory with filenames like ${name}.{key,crt,chain}
```

## Operational Security

Keeping the source of your certificates secure is, for obvious reasons,
important. `letsencrypt-aws` relies heavily on the AWS APIs to do its
business, so we recommend running this code from EC2 or Lambda, so that you
can use temporary credentials for an IAM role.

You need to make sure that the ACME account private key is kept secure. A
good choice is an S3 bucket with encryption enabled and access limited with
IAM.

Finally, wherever you're running `letsencrypt-aws` needs to be trusted.
`letsencrypt-aws` generates private keys in memory and uploads them to IAM
immediately, they are never stored on disk unless specifically requested
via the `--save-local-certs` option (which should only be used for testing)..

### IAM Policy

The minimum set of permissions needed for `letsencrypt-aws` to work is:

* `route53:ChangeResourceRecordSets`
* `route53:GetChange`
* `route53:ListHostedZones`
* `elasticloadbalancing:DescribeLoadBalancers`
* `elasticloadbalancing:SetLoadBalancerListenerSSLCertificate`
* `iam:DeleteServerCertificate`
* `iam:GetServerCertificate`
* `iam:ListServerCertificates`
* `iam:UpdateServerCertificate`
* `iam:UploadServerCertificate`

If your Let's Encrypt account key is provided as an `s3://` URI you will also
need:

* `s3:GetObject`

If that object is encrypted via KMS, you may also need KMS permissions. These
can be provided as part of the IAM policy, or as a resource policy on the KMS
key.

An example IAM policy is:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:GetChange",
                "route53:GetChangeDetails",
                "route53:ListHostedZones"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/*",
                "arn:aws:route53:::change/*"
            ]
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:SetLoadBalancerListenerSSLCertificate"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "iam:DeleteServerCertificate",
                "iam:GetServerCertificate",
                "iam:ListServerCertificates",
                "iam:UpdateServerCertificate",
                "iam:UploadServerCertificate"
            ],
            "Resource": [
                "arn:aws:iam::*:server-certificate/acme/*"
            ]
        }
    ]
}
```
