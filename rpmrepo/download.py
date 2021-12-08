from typing import Optional
from pathlib import Path
import sys
import createrepo_c as cr
from rpmrepo.metadata import MetadataParser
import tempfile
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import hashlib
from urllib.parse import urljoin
import asyncio
import ssl


from pkg_resources import get_distribution
import platform
from aiohttp import __version__ as aiohttp_version


def user_agent():
    """Produce a User-Agent string with relevant system info."""
    version = get_distribution("rpmrepo").version
    python = "{} {}.{}.{}-{}{}".format(sys.implementation.name, *sys.version_info)
    uname = platform.uname()
    system = f"{uname.system} {uname.machine}"
    return f"rpmrepo/{version} ({python}, {system}) (aiohttp {aiohttp_version})"


USER_AGENT = user_agent()


# TODO: missing features
# * proxies
# * TLS validation
# * timeouts
class DownloadConfig:
    allow_env_var: bool = False
    user_agent: str = USER_AGENT
    gpgcheck: bool = True
    verify_tls: bool = True
    tls_client_cert: Optional[Path] = None
    tls_client_key: Optional[Path] = None
    tls_ca_cert: Optional[Path] = None
    max_parallel_downloads: int = 10
    max_mirror_tries: int = 0
    max_parallel_downloads_per_mirror: int = 5

    def create_session(self, **kwargs):
        # default certificates are loaded if tls_ca_cert is None
        sslcontext = None
        if self.verify_tls:
            sslcontext = ssl.create_default_context(cafile=self.tls_ca_cert)
            if self.tls_client_cert:
                sslcontext.load_cert_chain(
                    certfile=self.tls_client_cert,
                    keyfile=self.tls_client_key
                )
        headers = {"user-agent": USER_AGENT}
        conn = aiohttp.TCPConnector(
            limit=self.max_parallel_downloads,
            limit_per_host=self.max_parallel_downloads_per_mirror,
            ssl=sslcontext,
        )
        session = aiohttp.ClientSession(
            connector=conn,
            trust_env=self.allow_env_var,
            headers=headers,
            **kwargs,
        )
        return session


# TODO: missing features
# * deltarpms
# * treeinfo
# * extra_files.json
# * multi stage downloads (metadata, then packages, without duplicating work)
# * gpgcheck
# * repo_gpgcheck
# * multimirror downloads
# * mirrorlists
# * progress reporting
# * list of URLs
class RepoDownloader:

    def __init__(self):
        self.session = None
        self.config = None

    @staticmethod
    def from_session(config: DownloadConfig, session: aiohttp.ClientSession):
        downloader = RepoDownloader()
        downloader.session = session
        downloader.config = config
        return downloader

    @staticmethod
    def from_config(config: DownloadConfig):
        downloader = RepoDownloader()
        downloader.session = config.create_session()
        downloader.config = config
        return downloader

    async def download_file(self, url, path):
        async with self.session.get(url) as resp:
            resp.raise_for_status()
            with open(path, 'wb') as fd:
                async for chunk in resp.content.iter_chunked(1024 * 1024):
                    fd.write(chunk)

    async def download_metadata(self, source, destination):
        repo_path = Path(destination)
        repodata_path = Path(destination) / "repodata"
        repodata_path.mkdir(parents=True, exist_ok=True)
        repomd_path = repodata_path / "repomd.xml"

        repodata_url = urljoin(source, "repodata/")
        repomd_url = urljoin(repodata_url, "repomd.xml")

        await self.download_file(repomd_url, repomd_path)

        repomd = cr.Repomd(str(repomd_path))
        records = {}
        downloaders = []

        # TODO: verify checksums, parallelize
        for record in repomd.records:
            url = urljoin(record.location_base or source, record.location_href)
            path = repo_path / record.location_href
            records[record.type] = path
            downloaders.append(self.download_file(url, path))

        await asyncio.gather(*downloaders)
        return {
            "repodata": records,
            "other": {}
        }

    async def yield_repository_files(packages=True):
        pass

    async def download_all(self, source, destination):
        # with tempfile.TemporaryDirectory() as e:
        # shutil.copytree(e, destination, dirs_exist_ok=True)

        await self.download_metadata(source, destination)

        repo_path = Path(destination)
        repodata_path = Path(destination) / "repodata"
        repodata_path.mkdir(parents=True, exist_ok=True)
        repomd_path = repodata_path / "repomd.xml"

        repomd = cr.Repomd(str(repomd_path))

        primary_xml_path = [record for record in repomd.records if record.type == "primary"][0].location_href

        parser = MetadataParser()
        parser._primary_xml_path = repo_path / primary_xml_path  # TODO

        downloaders = []

        for package in parser.parse_packages(only_primary=True).values():
            url = urljoin(package.location_base or source, package.location_href)
            path = repo_path / package.location_href
            downloaders.append(self.download_file(url, path))

        await asyncio.gather(*downloaders)

    async def __aenter__(self):
        await self.session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.__aexit__(exc_type, exc_value, traceback)


# url = "https://fixtures.pulpproject.org/rpm-unsigned/"
# config = rpmrepo.DownloadConfig()
# source = rpmrepo.RepoHandle.from_url(url)
# with rpmrepo.RepoDownloader.from_config(config) as downloader:
#     local = downloader.download_all(source, "foo/")
#     local.verify()


# url = "https://fixtures.pulpproject.org/rpm-unsigned/"
# config = rpmrepo.DownloadConfig()
# source = rpmrepo.RepoHandle.from_url(url)
# with aiohttp.ClientSession() as sessoin:
#     with RepoDownloader.from_session(session) as downloader:
#         local = downloader.download_all(source, "foo/")
#         local.verify()


# url = "https://fixtures.pulpproject.org/rpm-unsigned/"
# config = rpmrepo.DownloadConfig()
# with config.create_session() as session:
#     source = rpmrepo.RepoHandle.from_url(url, session)
#     local = source.download_all("foo/")

# url = "https://fixtures.pulpproject.org/rpm-unsigned/"
# with DownloadConfig().create_session() as session:
#     source = rpmrepo.RepoHandle.from_url(url, session):
#     local = source.download_all("foo/")


class RepoHandle:

    @staticmethod
    def from_mirrorlist_url(url: str, substitutions: dict):
        urls = []

        mirrorlist = session.get(url)

        for line in mirrorlist.lines():
            # remove leading and trailing whitespace
            line = line.strip()

            if not line:
                continue

            if "://" not in line and line[0] != "/":
                continue

            urls.append(line)

        handle = RemoteRepoHandle()
        handle.urls = urls
        return handle

    @staticmethod
    def from_url(url: str):
        handle = RemoteRepoHandle()
        handle.urls = [url]
        return handle

    @staticmethod
    def from_path(path: str):
        return LocalRepoHandle(Path(path))


class RemoteRepoHandle:

    def __init__(self, path: str):
        self.sources = []

class LocalRepoHandle:

    def __init__(self, path: Path):
        self.path: Path = path

    def verify_metadata_signature(self):
        # TODO: implementation
        # option to provide specific certificate chain?
        return True

    # TODO: allow missing option?
    def verify(self):
        parser = MetadataParser.from_repo(self.path)
        packages = list(parser.parse_packages(only_primary=True).values())
        metadata = parser.repomd.records

        checksum_to_hasher = {
            cr.MD5: hashlib.md5,
            cr.SHA: hashlib.sha1,
            cr.SHA1: hashlib.sha1,
            cr.SHA224: hashlib.sha224,
            cr.SHA256: hashlib.sha256,
            cr.SHA384: hashlib.sha384,
            cr.SHA512: hashlib.sha512,
        }

        def verify_file_checksum(path, hasher, expected):
            with path.open(mode='rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hasher.update(chunk)
            digest = hasher.hexdigest()
            return digest == expected

        def verify_package(pkg):
            path = self.path / pkg.location_href
            hasher = checksum_to_hasher[cr.checksum_type(pkg.checksum_type)]()
            expected = pkg.pkgId
            return verify_file_checksum(path, hasher, expected)

        def verify_metadata(record):
            path = self.path / record.location_href
            hasher = checksum_to_hasher[cr.checksum_type(record.checksum_type)]()
            expected = record.checksum
            return verify_file_checksum(path, hasher, expected)

        assert self.verify_metadata_signature(), "Failed to verify metadata signature"

        # TODO: do better than assertions
        with ThreadPoolExecutor() as exc:
            for metadata_file, verified in zip(metadata, exc.map(verify_metadata, metadata)):
                assert verified, "Failed checksum validation for {}".format(metadata_file.location_href)

            for pkg, verified in zip(packages, exc.map(verify_package, packages)):
                assert verified, "Failed checksum validation for {}".format(pkg.nevra())

        return True


PROGRESSBAR_LEN = 50


def callback(data, total_to_download, downloaded):
    """Progress callback"""
    if total_to_download <= 0:
        return
    completed = int(downloaded / (total_to_download / PROGRESSBAR_LEN))
    print("[{}{}] {:8s}/{:8s} ({})\r".format(
        '#' * completed, '-' * (PROGRESSBAR_LEN - completed),
        int(downloaded),
        int(total_to_download),
        data
    ))
    sys.stdout.flush()


def download_repo(url, destination, config=None, only_metadata=False):
    if config is None:
        config = DownloadConfig()

    ###############################

    async def main():
        async with RepoDownloader.from_config(config) as downloader:
            try:
                if only_metadata:
                    await downloader.download_metadata(url, destination)
                else:
                    await downloader.download_all(url, destination)
            except aiohttp.ClientResponseError as e:
                print(str(e))  # TODO: better formatted error message
                sys.exit(1)

    if sys.version_info.minor == 6:
        # 3.6
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    else:
        # 3.7+
        asyncio.run(main())
