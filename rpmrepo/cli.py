import json
import os
import sys
from pathlib import Path

import click
from humanfriendly import format_size

from .check import check_repository_metadata
from .stats import collect_repo_stats


@click.group()
def cli():
    pass


@click.command()
@click.argument('destination', type=click.Path())
@click.argument('url', type=str)
@click.option('--concurrency', type=int, default=0, help='How many files can be downloaded in parallel')
@click.option(
    '--tls-ca-cert',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help='Specify a TLS CA cert location (if not present in system trust store)')
@click.option(
    '--tls-client-cert',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help='Specify a TLS client cert location (.pem, .crt, .cert)')
@click.option(
    '--tls-client-cert-key',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help='Specify a TLS client key location (.pem, .key). Not needed if the cert file contains an embedded key.'
)
@click.option('--only-metadata', default=False, is_flag=True, help='Download metadata only')
@click.option('--no-check-certificate', default=False, is_flag=True, help='Disable TLS server certificate verification')
def download(
    destination,
    url,
    concurrency,
    tls_ca_cert,
    tls_client_cert,
    tls_client_cert_key,
    only_metadata,
    no_check_certificate,
):
    from .download import download_repo, DownloadConfig
    from pathlib import Path

    config = DownloadConfig()
    config.verify_tls = not no_check_certificate
    config.tls_ca_cert = tls_ca_cert
    config.tls_client_cert = tls_client_cert
    config.tls_client_key = tls_client_cert_key
    config.gpgcheck = False
    if concurrency:
        config.concurrency = concurrency

    download_repo(url, Path(destination), config=config, only_metadata=only_metadata)


# @click.option('--signatures', is_flag=True, help='Only verify signatures')
# @click.option('--checksums', is_flag=True, help='Only verify checksums')
# @click.option('--strict', is_flag=True, help='Turn most warnings into errors')
@click.command()
@click.argument('path', required=False, type=click.Path())
def check(path):
    # TODO:
    # * security mode - disallowed checksums (warning?)
    # * provide specific keys to verify against

    repo_path = Path(path) if path else Path(os.getcwd())
    (warnings, errors) = check_repository_metadata(repo_path)

    for error in errors:
        click.secho("[ERROR] ", fg='bright_red', bold=True, nl=False)
        click.secho(error)
        # click.secho()

    for warning in warnings:
        click.secho("[WARNING] ", fg='bright_yellow', bold=True, nl=False)
        click.secho(warning)
        # click.secho()

    # TODO: decide which layer to manage error messages in (Wrapper types with str() or just passing strings around)

    if errors:  # or (warnings and strict):
        sys.exit(1)


@click.command()
@click.argument('path', required=False, type=click.Path())
@click.option('--json', 'json_formatting', default=False, is_flag=True, help='Output raw JSON.')
def stats(path, json_formatting):
    repo_path = Path(path) if path else Path(os.getcwd())
    stats = collect_repo_stats(repo_path)

    def format_stats(stats):
        data = []
        data.append(("Number of packages:", str(stats["number_packages"])))
        data.append(("Packages total size:", format_size(stats["packages_total_size"])))

        if "metadata_total_size" in stats:
            data.append(("Metadata total size:", format_size(stats["metadata_total_size"])))

        if "metadata_total_size_decompressed" in stats:
            data.append(("Metadata total size (decompressed):", format_size(stats["metadata_total_size_decompressed"])))

        print()
        widths = [max(map(len, col)) for col in zip(*data)]
        for row in data:
            print("  ".join((val.ljust(width) for val, width in zip(row, widths))))
        print()

    if json_formatting:
        print(json.dumps(stats, indent=4))
    else:
        format_stats(stats)


cli.add_command(download)
cli.add_command(check)
cli.add_command(stats)


if __name__ == '__main__':
    cli()
