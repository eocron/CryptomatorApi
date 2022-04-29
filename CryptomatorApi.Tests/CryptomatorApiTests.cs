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
        private CryptomatorApiFactory _apiFactory;

        [SetUp]
        public void Setup()
        {
            _apiFactory = new CryptomatorApiFactory(new SimpleFileProvider(), new PathHelper(Path.DirectorySeparatorChar));
        }

        public static IEnumerable<TestCaseData> GetTests()
        {
            var folders = Directory.GetDirectories("Data/Cryptomator");
            foreach (var folder in folders)
            {
                var test = File.ReadAllText(Path.Combine(folder, "test.json"));
                var obj = JsonConvert.DeserializeObject<TestDto>(test);
                yield return new TestCaseData(obj, folder)
                    .SetName(Path.GetFileName(folder));
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
        [TestCaseSource(nameof(GetTests))]
        public async Task CheckContent(TestDto testCase, string folder)
        {
            var ct = CancellationToken.None;
            var actualHashes = new Dictionary<string, string>();
            var api = _apiFactory.Create(testCase.Password, folder);
            await foreach (var (file, hash) in GetFileAndHashes(api, null, ct))
            {
                actualHashes.Add(file, hash);
            }

            actualHashes.Should().BeEquivalentTo(testCase.Hashes);
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

        private async IAsyncEnumerable<(string, string)> GetFileAndHashes(ICryptomatorApi api, string path, [EnumeratorCancellation] CancellationToken ct)
        {

            await foreach (var file in api.GetFiles(path, ct))
            {
                var tmpFile = Path.GetTempFileName();
                try
                {
                    await using var fileStream = await api.OpenReadAsync(file.FullName, ct).ConfigureAwait(false);
                    var actualHash = GetMd5Hash(fileStream);
                    yield return (file.FullName, actualHash);
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

        private string GetMd5Hash(Stream stream)
        {
            using var md5 = MD5.Create();
            var hash = md5.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        public class TestDto
        {
            public string Password { get; set; }

            public Dictionary<string, string> Hashes { get; set; }

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