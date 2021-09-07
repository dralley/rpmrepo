import aiohttp
import pytest

import rpmrepo


# TODO: use an actual randomized temporary directory

@pytest.mark.asyncio
async def test_invalid_url():
    url = "https://fixtures.pulpproject.org/not-a-repo-that-exists/"
    config = rpmrepo.DownloadConfig()
    with pytest.raises(aiohttp.ClientResponseError) as excinfo:
        async with rpmrepo.RepoDownloader.from_config(config) as downloader:
            await downloader.download_all(url, "/tmp/foo/")
    assert excinfo.value.status == 404


@pytest.mark.asyncio
async def test_normal():
    url = "https://fixtures.pulpproject.org/rpm-unsigned/"
    config = rpmrepo.DownloadConfig()
    async with rpmrepo.RepoDownloader.from_config(config) as downloader:
        await downloader.download_all(url, "/tmp/bar/")
    # TODO: check for the existence of expected files
