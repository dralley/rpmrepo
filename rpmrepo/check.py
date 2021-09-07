from pathlib import Path
from collections import defaultdict
import itertools

from rpmrepo.metadata import MetadataParser


INSECURE_CHECKSUMS = {'md5', 'sha', 'sha1'}


def check_repository_metadata(repo_path: Path):
    warnings = []
    errors = []

    parser = MetadataParser.from_repo(repo_path)
    checksum_types_used = set()

    for record in parser.repomd.records:
        checksum_types_used.add(record.checksum_type)

    if len(checksum_types_used) > 1:
        warnings.append(
            "Multiple checksum types {} are used for metadata".format(tuple(checksum_types_used))
        )

    insecure_checksums_used = checksum_types_used.intersection(INSECURE_CHECKSUMS)
    if insecure_checksums_used:
        warnings.append(
            "Insecure checksum type '{}' is used for metadata".format(', '.join(insecure_checksums_used))
        )
    checksum_types_used = set()

    nevra_occurences = defaultdict(list)

    def package_cb(pkg):
        checksum_types_used.add(pkg.checksum_type)
        nevra_occurences[pkg.nevra()].append(pkg.pkgId)

        num_files = len(pkg.files)
        num_unique_files = len(set(pkg.files))
        if num_unique_files != num_files:
            errors.append(
                "Package '{}' has duplicated 'file' entries: {} unique paths out of {} total.".format(
                    pkg.nevra(), num_unique_files, num_files
                )
            )

    warnings = parser.for_each_package(package_cb)

    insecure_checksums_used = checksum_types_used.intersection(INSECURE_CHECKSUMS)
    if insecure_checksums_used:
        warnings.append(
            "Insecure checksum type '{}' is used for packages".format(', '.join(insecure_checksums_used))
        )

    # In order to give more helpful information to the user, we want to distinguish between the
    # situation where one NEVRA is added with multiple different pkgids, and the situation where
    # the same package is listed multiple times in the metadata. It's probably safe to assume that
    # you cannot have duplicate pkgId without duplicate NEVRA.
    duplicate_nevra = {
        nevra: pkgids for nevra, pkgids in nevra_occurences.items()
        if len(pkgids) > 1
    }

    def all_equal(iterable):
        g = itertools.groupby(iterable)
        return next(g, True) and not next(g, False)

    for nevra, pkgids in duplicate_nevra.items():
        if all_equal(pkgids):
            errors.append(
                "Duplicate package '{nevra}'\n appears {count} times with pkgid '{pkgid}'".format(
                    nevra=nevra, count=len(pkgids), pkgid=pkgids[0])
            )
        else:
            errors.append(
                "Duplicate package '{nevra}'\n appears {count} times with pkgids {pkgids}".format(
                    nevra=nevra, count=len(pkgids), pkgids=pkgids)
            )

    # TODO: check signatures of packages + metadata
    # TODO: maybe warn about unsigned metadata?
    # TODO: maybe warn about # / age of changelogs (to avoid repo bloat)

    return (warnings, errors)
