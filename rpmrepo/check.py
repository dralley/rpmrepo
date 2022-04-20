from pathlib import Path
from collections import defaultdict
import itertools

from rpmrepo.metadata import MetadataParser


INSECURE_CHECKSUMS = {'md5', 'sha', 'sha1'}


def check_repository_metadata(repo_path: Path, errata_check=None):
    warnings = []
    errors = []

    parser = MetadataParser.from_repo(repo_path)
    checksum_types_used = set()

    packages_with_advisories = defaultdict(set)
    packages_without_advisories = defaultdict(set)

    def format_nevra(name, epoch, version, release, arch):
        return "{name}-{epoch}{version}-{release}.{arch}".format(
            name=name,
            epoch=f"{epoch}:" if epoch else "0:",
            version=version,
            release=release,
            arch=arch,
        )

    if errata_check:
        for record in parser.advisories():
            for collection in record.collections:
                for package in collection.packages:
                    nevra = format_nevra(package.name, package.epoch, package.version, package.release, package.arch)
                    packages_with_advisories[package.name].add(nevra)

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
    package_occurrences = defaultdict(list)

    warnings = []

    def warningcb(warning_type, message):
        """Optional callback for warnings about wierd stuff and formatting in XML.

        Args:
            warning_type (int): One of the XML_WARNING_* constants.
            message (str): Message.
        """
        warnings.append((warning_type, message))
        return True  # continue parsing

    for pkg in parser.iter_packages(warningcb=warningcb):
        checksum_types_used.add(pkg.checksum_type)
        nevra_occurences[pkg.nevra()].append(pkg.pkgId)
        package_occurrences[pkg.name].append(pkg)

        num_files = len(pkg.files)
        num_unique_files = len(set(pkg.files))
        if num_unique_files != num_files:
            errors.append(
                "Package '{}' has duplicated 'file' entries: {} paths listed but only {} are unique.".format(
                    pkg.nevra(), num_files, num_unique_files
                )
            )

    if errata_check:
        for name, packages in package_occurrences.items():
            packages.sort(key=lambda x: x.nevra())
            for package in packages:
                if package.time_build > errata_check and package.nevra() not in packages_with_advisories[name]:
                    packages_without_advisories[name].add(package.nevra())

        for name in sorted(list(packages_without_advisories.keys())):
            packages = packages_without_advisories[name]
            for package in packages:
                warnings.append("Package '{}' is not covered by an errata.".format(package))

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
