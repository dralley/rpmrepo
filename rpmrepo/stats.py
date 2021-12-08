import sys
from pathlib import Path

import createrepo_c as cr

from rpmrepo.metadata import MetadataParser


def collect_repo_stats(repo_path: Path):
    parser = MetadataParser.from_repo(repo_path)

    data = {
        "changelog_bytes_saved": 0,
        "changelog_description_bytes": 0,
        "total_changelogs": 0,
        "total_file_entries": 0,
        "file_path_bytes": 0,
        "unique_authors": set(),
        "package_with_most_changelogs": {},
        "package_with_most_files": {},
        "number_packages": 0,
        "packages_total_size": 0,
    }

    def package_callback(pkg):
        unique_authors = set()
        changelog_bytes_saved = 0
        total_changelogs = 0
        changelog_description_bytes = 0
        total_file_entries = 0
        file_path_bytes = 0

        for changelog in pkg.changelogs:
            author = changelog[cr.CHANGELOG_ENTRY_AUTHOR]
            if author in unique_authors:
                changelog_bytes_saved += sys.getsizeof(author)
            unique_authors.add(author)
            total_changelogs += 1
            changelog_description_bytes += sys.getsizeof(changelog[cr.CHANGELOG_ENTRY_CHANGELOG])

        for f in pkg.files:
            total_file_entries += 1
            file_path_bytes += sys.getsizeof(f[cr.FILE_ENTRY_PATH])

        data["changelog_bytes_saved"] += changelog_bytes_saved
        data["total_changelogs"] += total_changelogs
        data["number_packages"] += 1
        data["unique_authors"] |= unique_authors
        data["changelog_description_bytes"] += changelog_description_bytes
        data["total_file_entries"] += total_file_entries
        data["file_path_bytes"] += file_path_bytes
        data["packages_total_size"] += pkg.size_package

        if data["package_with_most_files"].get("files", 0) < total_file_entries:
            data["package_with_most_files"]["files"] = total_file_entries
            data["package_with_most_files"]["nevra"] = pkg.nevra()

        if data["package_with_most_changelogs"].get("changelogs", 0) < total_changelogs:
            data["package_with_most_changelogs"]["changelogs"] = total_changelogs
            data["package_with_most_changelogs"]["nevra"] = pkg.nevra()

    parser.for_each_package(package_callback)

    metadata_total_size = 0
    metadata_total_size_decompressed = 0

    for record in parser.repomd:
        if record.size and record.size != -1:
            metadata_total_size += record.size
        if record.size_open != -1:
            metadata_total_size_decompressed += record.size_open

    if metadata_total_size:
        data["metadata_total_size"] = metadata_total_size
    if metadata_total_size_decompressed:
        data["metadata_total_size_decompressed"] = metadata_total_size_decompressed

    data["unique_authors"] = len(data["unique_authors"])

    return data
