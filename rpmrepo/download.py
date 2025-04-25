import asyncio
import aiofiles
import aiofiles.os
import enum
import hashlib
import json
import platform
import sys
import ssl
import tempfile
import os

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from pkg_resources import get_distribution
from typing import Optional
from urllib.parse import urljoin

import aiohttp
from aiohttp import __version__ as aiohttp_version
import createrepo_c as cr


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
# * timeouts
# * progress reporting on individual files?
class DownloadConfig:
    auth_token: str = None
    allow_env_var: bool = False
    user_agent: str = USER_AGENT
    verify_tls: bool = True
    tls_client_cert: Optional[Path] = None
    tls_client_key: Optional[Path] = None
    tls_ca_cert: Optional[Path] = None
    max_parallel_downloads: int = 8
    max_mirror_tries: int = 0
    max_parallel_downloads_per_mirror: int = 5

    def create_session(self, **kwargs):
        # default certificates are loaded if tls_ca_cert is None
        sslcontext = False
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
            timeout=aiohttp.ClientTimeout(total=None),
            **kwargs,
        )
        return session


# TODO: unclear whether this ought to be separate or part of DownloadContext - good arguments both ways
# if everything merged together:
# * interaction with downloadcontext could be cleaner
# * no longer need to provide a session argument on methods
# but:
# * feels like separate information
# * would encourage throwing away the download context instead of reusing it, feels kinda weird
class MirrorContext:

    def __init__(self):
        # self.mirrors = defaultdict(int)
        self.mirrors = []

    def from_urls(*sources):
        source = MirrorContext()
        source.mirrors.extend(sources)
        return source

    # def mark_failure(self, mirror):
    #     self.mirrors[mirror] += 1

    def urls_for_relative_path(self, rel_path):
        # pick the mirrors with the least failures first
        # for mirror, _ in sorted(self.mirrors.items(), key=lambda m: m[1]):
        #     yield urljoin(mirror, rel_path)

        for mirror in self.mirrors:
            yield urljoin(mirror, rel_path)

    @staticmethod
    async def from_mirrorlist_url(mirrorlist_url: str, session: aiohttp.ClientSession):
        # TODO: url component substitutions
        source = MirrorContext()
        async with session.get(mirrorlist_url) as resp:
            mirrorlist = await resp.text()

            for line in mirrorlist.splitlines():
                # remove leading and trailing whitespace
                line = line.strip()

                if not line:
                    continue

                if "://" not in line and line[0] != "/":
                    continue

                source.mirrors.append(line)
        return source

    @staticmethod
    async def from_metalink_url(metalink_url: str, session: aiohttp.ClientSession):
        # TODO
        pass


# TODO:
# * retry / multimirror handling
class DownloadContext:
    def __init__(self):
        self.session = None
        self.config = None

    @staticmethod
    def from_session(session: aiohttp.ClientSession):
        ctx = DownloadContext()
        ctx.session = session
        return ctx

    @staticmethod
    def from_config(config: DownloadConfig):
        ctx = DownloadContext()
        ctx.session = config.create_session()
        ctx.config = config
        return ctx

    async def mirrored_download(self, mirrors: MirrorContext, rel_path: str, path: Path, allow_fail=False):
        # TODO: fancy fallback stuff
        for mirror, url in zip(mirrors.mirrors, mirrors.urls_for_relative_path(rel_path)):
            try:
                return await self.download(url, path, allow_fail=allow_fail)
            except Exception:  # TODO: should this be tightened up?
                # mirrors.mark_failure(mirror)
                continue

        raise Exception("Download failed for \"{}\" - all mirrors tried".format(rel_path))

    async def download(self, url: str, path: Path, allow_fail=False):
        # TODO: allow_fail is inflexible
        if self.config.auth_token is not None:
            url = url + f"?{self.config.auth_token}"
        await aiofiles.os.makedirs(os.path.dirname(path), exist_ok=True)
        async with self.session.get(url) as resp:
            if allow_fail and resp.status in {403, 404}:
                return
            resp.raise_for_status()
            async with aiofiles.open(path, 'wb') as fd:
                async for chunk in resp.content.iter_chunked(1024 * 1024):
                    await fd.write(chunk)

    async def __aenter__(self):
        await self.session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.__aexit__(exc_type, exc_value, traceback)


class RepoOptions(enum.Flag):
    RepomdXML = enum.auto()
    PrimaryXML = enum.auto()
    FilelistsXML = enum.auto()
    OtherXML = enum.auto()
    MainXmlMetadata = RepomdXML | PrimaryXML | FilelistsXML | OtherXML

    # everything referenced by repomd.xml
    AllRpmMetadata = enum.auto()
    # everything not referenced by repomd.xml (treeinfo, extra_files.json, GPG keys)
    ExtraMetadata = enum.auto()

    AllMetadata = AllRpmMetadata | ExtraMetadata
    Packages = enum.auto()
    Everything = AllMetadata | Packages


# TODO: missing features
# * multi stage downloads (don't download things that are already there)
# * gpgcheck
# * repo_gpgcheck
# * progress reporting
class RepoDownloader:
    def __init__(self, download_context):
        self.ctx = download_context

    async def download_repo(self, mirrors: MirrorContext, destination: Path, options=RepoOptions.Everything):
        # TODO: put everything into a temporary directory before moving it to the destination?
        # with tempfile.TemporaryDirectory() as e:
        # shutil.copytree(e, destination, dirs_exist_ok=True)

        repo_path = Path(destination)
        repodata_path = repo_path / "repodata"
        repodata_path.mkdir(parents=True, exist_ok=True)
        repomd_path = repodata_path / "repomd.xml"

        # TODO: verify checksums, add to report
        # TODO: handle the files .treeinfo points to

        await self.ctx.mirrored_download(mirrors, "repodata/repomd.xml", repomd_path)

        if options & RepoOptions.ExtraMetadata:
            for name in ("repomd.xml.asc", "repomd.xml.key"):
                await self.ctx.mirrored_download(mirrors, "repodata/" + name, repodata_path / name, allow_fail=True)

            for name in (".treeinfo", "treeinfo"):
                await self.ctx.mirrored_download(mirrors, name, repo_path / name, allow_fail=True)

            # try:
            #     await self.mirrored_download(urljoin(source, "extra_files.json"), "extra_files.json")
            #     with open("extra_files.json", "r") as f:
            #         extra_files = json.loads(f.read())
            #         for data in extra_files["data"]:
            #             await self.mirrored_download(urljoin(source, data["file"]), data["file"])
            # except Exception:
            #     pass

        parser = cr.RepositoryReader.from_path(repo_path)
        handle = LocalRepoHandle(repo_path)

        records = {}
        downloaders = []

        def include_md_file(mdtype: str, options: RepoOptions):
            if options & RepoOptions.AllRpmMetadata:
                return True

            if mdtype == "primary":
                return options & RepoOptions.PrimaryXML
            elif mdtype == "filelists":
                return options & RepoOptions.FilelistsXML
            elif mdtype == "other":
                return options & RepoOptions.OtherXML

            return False

        # TODO: verify checksums
        for record in parser.repomd.records:
            if not include_md_file(record.type, options):
                continue
            path = repo_path / record.location_href
            records[record.type] = path
            if record.location_base:
                url = urljoin(record.location_base, record.location_href)
                downloader = self.ctx.download(url, path)
            else:
                downloader = self.ctx.mirrored_download(mirrors, record.location_href, path)
            downloaders.append(downloader)

        await asyncio.gather(*downloaders)

        if options & RepoOptions.Packages:
            downloaders = []
            for package in parser.parse_packages(only_primary=True).values():
                path = repo_path / package.location_href
                if await aiofiles.os.path.exists(path):
                    if handle.verify_package(package):
                        continue
                if package.location_base:
                    url = urljoin(package.location_base, package.location_href)
                    downloader = self.ctx.download(url, path)
                else:
                    downloader = self.ctx.mirrored_download(mirrors, package.location_href, path)
                downloaders.append(downloader)

            await asyncio.gather(*downloaders)
            return handle

    async def __aenter__(self):
        await self.ctx.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.ctx.__aexit__(exc_type, exc_value, traceback)


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


class LocalRepoHandle:

    def __init__(self, path: Path):
        self.path: Path = path

    def verify_metadata_signature(self):
        # TODO: implementation
        # option to provide specific certificate chain?
        return True

    # TODO: allow missing option?
    def verify(self):
        parser = cr.RepositoryReader.from_path(self.path)
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

        def verify_file_checksum(path, hasher, expected: str):
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

        def verify_metadata_record(record):
            path = self.path / record.location_href
            hasher = checksum_to_hasher[cr.checksum_type(record.checksum_type)]()
            expected = record.checksum
            return verify_file_checksum(path, hasher, expected)

        assert self.verify_metadata_signature(), "Failed to verify metadata signature"

        # TODO: do better than assertions
        with ThreadPoolExecutor() as exc:
            for record, verified in zip(metadata, exc.map(verify_metadata_record, metadata)):
                assert verified, "Failed checksum validation for {}".format(record.location_href)

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


def download_repo(url, destination, config=None, options=RepoOptions.Everything):
    if config is None:
        config = DownloadConfig()

    ###############################

    async def main():
        ctx = DownloadContext.from_config(config)
        async with RepoDownloader(ctx) as downloader:
            # if "mirrorlist" in url:
            #     source = await MirrorContext.from_mirrorlist_url(url, ctx.session)
            # else:
            source = MirrorContext.from_urls(url)

            try:
                await downloader.download_repo(source, destination, options=options)
            except aiohttp.ClientResponseError as e:
                print(str(e))  # TODO: better formatted error message
                sys.exit(1)

    asyncio.run(main())
