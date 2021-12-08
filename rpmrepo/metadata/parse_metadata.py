import collections
import logging

import createrepo_c as cr

log = logging.getLogger(__name__)


class MetadataParser:
    """Parser for RPM metadata."""

    def __init__(self):
        """Initialize empty (use one of the alternate constructors)."""
        self._primary_xml_path = None
        self._filelists_xml_path = None
        self._other_xml_path = None
        self.repomd = None

    @staticmethod
    def from_repo(path):
        repomd_path = path / "repodata" / "repomd.xml"
        if not repomd_path.exists():
            raise FileNotFoundError("No repository found at the provided path.")

        repomd = cr.Repomd(str(repomd_path))
        metadata_files = {record.type: record for record in repomd.records}
        parser = MetadataParser()
        parser._primary_xml_path = path / metadata_files["primary"].location_href
        parser._filelists_xml_path = path / metadata_files["filelists"].location_href
        parser._other_xml_path = path / metadata_files["other"].location_href
        parser.repomd = repomd
        return parser

    @staticmethod
    def from_metadata_files(primary_xml_path, filelists_xml_path, other_xml_path):
        """Construct a parser from the three main metadata files."""
        parser = MetadataParser()
        parser._primary_xml_path = primary_xml_path
        parser._filelists_xml_path = filelists_xml_path
        parser._other_xml_path = other_xml_path
        return parser

    def count_packages(self):
        """Count the total number of packages."""
        # It would be much faster to just read the number in the header of the metadata.
        # But there's no way to do that, and also we can't necessarily rely on that number because
        # of duplicates.
        len(self.parse_packages(only_primary=True))

    def for_each_package(self, pkgcb):
        """Run a callback for each complete package encountered during metadata parsing."""
        warnings = []

        def warningcb(warning_type, message):
            """Optional callback for warnings about wierd stuff and formatting in XML.

            Args:
                warning_type (int): One of the XML_WARNING_* constants.
                message (str): Message.
            """
            warnings.append((warning_type, message))
            return True  # continue parsing

        cr.xml_parse_main_metadata_together(
            str(self._primary_xml_path),
            str(self._filelists_xml_path),
            str(self._other_xml_path),
            None,
            pkgcb,
            warningcb,
        )
        return warnings

    def parse_packages(self, only_primary=False):
        """
        Parse repodata to extract package info.

        Args:
            primary_xml_path (str): a path to a downloaded primary.xml
            filelists_xml_path (str): a path to a downloaded filelists.xml
            other_xml_path (str): a path to a downloaded other.xml

        Kwargs:
            only_primary (bool): If true, only the metadata in primary.xml will be parsed.

        Returns:
            dict: createrepo_c package objects with the pkgId as a key

        """

        warnings = []

        def warningcb(warning_type, message):
            """Optional callback for warnings about wierd stuff and formatting in XML.

            Args:
                warning_type (int): One of the XML_WARNING_* constants.
                message (str): Message.
            """
            warnings.append((warning_type, message))
            return True  # continue parsing

        def pkgcb(pkg):
            """
            A callback which is used when a whole package entry in xml is parsed.

            Args:
                pkg(preaterepo_c.Package): a parsed metadata for a package

            """
            packages[pkg.pkgId] = pkg

        def newpkgcb(pkgId, name, arch):
            """
            A callback which is used when a new package entry is encountered.

            Only opening <package> element is parsed at that moment.
            This function has to return a package which parsed data will be added to
            or None if a package should be skipped.

            pkgId, name and arch of a package can be used to skip further parsing. Available
            only for filelists.xml and other.xml.

            Args:
                pkgId(str): pkgId of a package
                name(str): name of a package
                arch(str): arch of a package

            Returns:
                createrepo_c.Package: a package which parsed data should be added to.

                If None is returned, further parsing of a package will be skipped.

            """
            return packages.get(pkgId, None)

        packages = collections.OrderedDict()

        cr.xml_parse_primary(str(self._primary_xml_path), pkgcb=pkgcb, warningcb=warningcb, do_files=False)
        if not only_primary:
            cr.xml_parse_filelists(str(self._filelists_xml_path), newpkgcb=newpkgcb, warningcb=warningcb)
            cr.xml_parse_other(str(self._other_xml_path), newpkgcb=newpkgcb, warningcb=warningcb)
        return packages

    def yield_packages(self, only_primary=False):
        """Iterate the packages in the original order in which they were parsed."""
        packages = self.parse_packages(only_primary=only_primary)
        while True:
            try:
                (pkgid, pkg) = packages.popitem(last=False)
            except KeyError:
                break

            yield pkg
