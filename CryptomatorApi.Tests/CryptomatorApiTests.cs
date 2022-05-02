using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;
using CryptomatorApi.Providers;
using FluentAssertions;
using Newtonsoft.Json;
using NUnit.Framework;

namespace CryptomatorApi.Tests
{
    public class CryptomatorApiTests
    {
        private ICryptomatorApiFactory _apiFactory;

        [SetUp]
        public void Setup()
        {
            _apiFactory = new CryptomatorApiFactory(new SimpleFileProvider(), new PathHelper());
        }

        public static IEnumerable<TestCaseData> GetTests()
        {
            var folders = Directory.GetDirectories("Data/Cryptomator");
            foreach (var folder in folders)
            {
                var test = File.ReadAllText(Path.Combine(folder, "test.json"));
                var obj = JsonConvert.DeserializeObject<TestDto>(test);
                var originalsFolder = Path.Combine(folder, "originals");
                var hashes = GetFileAndHashes(originalsFolder, CancellationToken.None);
                obj.Checks = hashes.Select(x => $"{x.Item1.Substring(originalsFolder.Length + 1)} {x.Item2} {x.Item3}").ToList();
                var vaultPath = Path.Combine(folder, "encrypted");
                yield return new TestCaseData(obj, vaultPath, originalsFolder)
                    .SetName(Path.GetFileName(folder));
            }
        }

        public static IEnumerable<TestCaseData> GetSeekTests()
        {
            var seekOrigins = new[]
            {
                SeekOrigin.Begin, 
                SeekOrigin.Current,
                SeekOrigin.End
            };
            var offsets = new[]
            {
                0,
                1,
                32768,
                5129951 - 1,
                5129951,
                5129951 + 1,
            };
            var bufferSizes = new[]
            {
                1,
                32768 - 1,
                32768,
                32768 + 1,
                32768 + 48 - 1,
                32768 + 48,
                32768 + 48 + 1,
                5129951 - 1,
                5129951,
                5129951 + 1,
            };

            foreach (var seekOrigin in seekOrigins)
            {
                foreach (var offset in offsets)
                {
                    foreach (var bufferSize in bufferSizes)
                    {
                        yield return new TestCaseData(seekOrigin, (seekOrigin == SeekOrigin.End) ? -offset : offset, bufferSize);
                    }
                }
            }
        }

        public static IEnumerable<TestCaseData> GetSearchTests()
        {
            foreach (var tc in GetTests())
            {
                var obj = (TestDto)tc.Arguments[0];
                var folder = (string)tc.Arguments[1];
                foreach (var stc in obj.AllSearches ?? Enumerable.Empty<TestSearchDto>())
                {
                    yield return new TestCaseData(nameof(obj.AllSearches), obj.Password, folder, stc)
                        .SetName(GetName("All", folder, stc));
                }

                foreach (var stc in obj.DirectorySearches ?? Enumerable.Empty<TestSearchDto>())
                {
                    yield return new TestCaseData(nameof(obj.DirectorySearches), obj.Password, folder, stc)
                        .SetName(GetName("Directory", folder, stc));
                }

                foreach (var stc in obj.FileSearches ?? Enumerable.Empty<TestSearchDto>())
                {
                    yield return new TestCaseData(nameof(obj.FileSearches), obj.Password, folder, stc)
                        .SetName(GetName("File", folder, stc));
                }
            }
        }

        private static string GetName(string type, string folder, TestSearchDto stc)
        {
            var sb = new StringBuilder();
            sb.Append(Path.GetFileName(folder));
            sb.Append(" ");
            sb.Append(type);
            sb.Append(" search for '");
            sb.Append(stc.FolderPath);
            if (stc.SearchOption == SearchOption.AllDirectories)
            {
                if (!stc.FolderPath.EndsWith('/') && !string.IsNullOrWhiteSpace(stc.FolderPath))
                    sb.Append('/');
                sb.Append("**/");
            }
            sb.Append(stc.Wildcard);
            sb.Append('\'');
            return sb.ToString();
        }

        [Test]

        [TestCaseSource(nameof(GetSeekTests))]
        public async Task Seek(SeekOrigin origin, int offset, int bufferSize)
        {
            var ct = CancellationToken.None;
            var api = _apiFactory.Create("testtest", "Data/Cryptomator/01/encrypted");
            var originalFilePath = "Data/Cryptomator/01/originals/big_file.bin";
            var encryptedVirtualPath = "big_file.bin";

            await using var actualStream = await api.OpenReadAsync(encryptedVirtualPath, ct).ConfigureAwait(false);
            await using var expectedStream = File.OpenRead(originalFilePath);

            Exception actualEx = null;
            Exception expectedEx = null;
            try
            {
                actualStream.Seek(offset, origin);
            }
            catch(Exception ex)
            {
                actualEx = ex;
            }
            try
            {
                expectedStream.Seek(offset, origin);
            }
            catch (Exception ex)
            {
                expectedEx = ex;
            }

            if (expectedEx != null)
            {
                Assert.AreEqual(expectedEx?.GetType(), actualEx?.GetType());
                return;
            }
            
            if (origin == SeekOrigin.Current)
            {
                actualStream.Seek(offset, origin);
                expectedStream.Seek(offset, origin);
            }

            var actual = await GetMd5Hash(actualStream, bufferSize, ct).ConfigureAwait(false);
            var expected = await GetMd5Hash(expectedStream, ct).ConfigureAwait(false);
            CollectionAssert.AreEqual(expected, actual);
        }

        [Test]
        [TestCaseSource(nameof(GetTests))]
        public async Task CheckContent(TestDto testCase, string vaulePath, string originalsPath)
        {
            var ct = CancellationToken.None;
            var actualHashes = new List<string>();
            var api = _apiFactory.Create(testCase.Password, vaulePath);
            await foreach (var (file, hash, size) in GetFileAndHashes(api, null, ct))
            {
                actualHashes.Add($"{file} {hash} {size}");
            }
            actualHashes.Should().BeEquivalentTo(testCase.Checks);
        }


        [Test]
        [TestCaseSource(nameof(GetSearchTests))]
        public async Task Search(string type, string password, string folder, TestSearchDto testCase)
        {
            var ct = CancellationToken.None;
            var api = _apiFactory.Create(password, folder);

            var tmp = new List<string>();
            switch (type)
            {
                case nameof(TestDto.AllSearches):
                    await foreach (var item in api.GetFileSystemInfos(testCase.FolderPath, testCase.Wildcard, testCase.SearchOption, ct))
                    {
                        tmp.Add(item.FullName);
                    }
                    break;
                case nameof(TestDto.FileSearches):
                    await foreach (var item in api.GetFiles(testCase.FolderPath, testCase.Wildcard, testCase.SearchOption, ct))
                    {
                        tmp.Add(item.FullName);
                    }
                    break;
                case nameof(TestDto.DirectorySearches):
                    await foreach (var item in api.GetDirectories(testCase.FolderPath, testCase.Wildcard, testCase.SearchOption, ct))
                    {
                        tmp.Add(item.FullName);
                    }
                    break;
                default: throw new ArgumentException(type);
            }

            tmp.Should().BeEquivalentTo(testCase.ExpectedResult);
        }

        private static IEnumerable<(string, string, long)> GetFileAndHashes(string folder, CancellationToken ct)
        {
            foreach (var file in Directory.GetFiles(folder))
            {
                var tmpFile = Path.GetTempFileName();
                try
                {
                    using var fileStream = File.OpenRead(file);
                    var length = fileStream.Length;
                    var actualHash = GetMd5Hash(fileStream, ct).Result;
                    yield return (file, actualHash, length);
                }
                finally
                {
                    File.Delete(tmpFile);
                }
            }

            foreach (var f in Directory.GetDirectories(folder))
            {
                foreach (var file in GetFileAndHashes(f, ct))
                {
                    yield return file;
                }
            }
        }

        private static async IAsyncEnumerable<(string, string, long)> GetFileAndHashes(ICryptomatorApi api, string path, [EnumeratorCancellation] CancellationToken ct)
        {

            await foreach (var file in api.GetFiles(path, ct))
            {
                var tmpFile = Path.GetTempFileName();
                try
                {
                    await using var fileStream = await api.OpenReadAsync(file.FullName, ct).ConfigureAwait(false);
                    var length = fileStream.Length;
                    var actualHash = await GetMd5Hash(fileStream, ct).ConfigureAwait(false);
                    yield return (file.FullName, actualHash, length);
                }
                finally
                {
                    File.Delete(tmpFile);
                }
            }

            await foreach (var folder in api.GetDirectories(path, ct))
            {
                await foreach (var file in GetFileAndHashes(api, folder.FullName, ct))
                {
                    yield return file;
                }
            }
        }

        private static async Task<string> GetMd5Hash(Stream stream, CancellationToken cancellationToken)
        {
            using var md5 = MD5.Create();
            var hash = await md5.ComputeHashAsync(stream, cancellationToken).ConfigureAwait(false);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private static async Task<string> GetMd5Hash(Stream stream, int bufferSize, CancellationToken cancellationToken)
        {
            using var md5 = MD5.Create();
            var buffer = new byte[bufferSize];
            int read;
            while ((read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                md5.TransformBlock(buffer, 0, read, null, 0);
            }

            md5.TransformFinalBlock(new byte[0], 0, 0);

            var hash = md5.Hash;
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        public class TestDto
        {
            public string Password { get; set; }
            public List<string> Checks { get; set; }
            public List<TestSearchDto> DirectorySearches { get; set; }
            public List<TestSearchDto> FileSearches { get; set; }
            public List<TestSearchDto> AllSearches { get; set; }
        }

        public class TestSearchDto
        {
            public string Wildcard { get; set; }
            public SearchOption SearchOption { get; set; }
            public List<string> ExpectedResult { get; set; }
            public string FolderPath { get; set; }
        }
    }
}