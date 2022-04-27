using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Newtonsoft.Json;
using NUnit.Framework;

namespace CryptomatorApi.Tests
{
    public class ContentCheckTests
    {
        private CryptomatorApiFactory _apiFactory;

        [SetUp]
        public void Setup()
        {
            _apiFactory = new CryptomatorApiFactory(new SimpleFileProvider());
        }

        public static IEnumerable<TestCaseData> GetTests()
        {
            var folders = Directory.GetDirectories("Data/Cryptomator");
            foreach (var folder in folders)
            {
                var test = File.ReadAllText(Path.Combine(folder, "test.json"));
                var obj = JsonConvert.DeserializeObject<TestDto>(test);
                yield return new TestCaseData(obj.Password, obj.Hashes, folder)
                    .SetName(Path.GetFileName(folder));
            }
        }

        [Test]
        [TestCaseSource(nameof(GetTests))]
        public async Task CheckCorrect(string password, Dictionary<string, string> expectedHashes, string folder)
        {
            var ct = CancellationToken.None;
            var actualHashes = new Dictionary<string, string>();
            var api = _apiFactory.Create(password, folder);

            await foreach (var file in GetAllFiles(api, "", ct))
            {
                actualHashes.Add(file.Key, file.Value);
            }
            
            actualHashes.Should().BeEquivalentTo(expectedHashes);
        }

        private async IAsyncEnumerable<KeyValuePair<string, string>> GetAllFiles(ICryptomatorApi api, string path, [EnumeratorCancellation] CancellationToken ct)
        {

            await foreach (var file in api.GetFiles(path, ct))
            {
                var tmpFile = Path.GetTempFileName();
                try
                {
                    await using var fileStream = await api.OpenReadAsync(file, ct).ConfigureAwait(false);
                    var actualHash = GetMd5Hash(fileStream);
                    yield return new KeyValuePair<string, string>(file, actualHash);
                }
                finally
                {
                    File.Delete(tmpFile);
                }
            }

            await foreach (var folder in api.GetFolders(path, ct))
            {
                await foreach (var file in GetAllFiles(api, folder.VirtualPath, ct))
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

        private class TestDto
        {
            public string Password { get; set; }

            public Dictionary<string, string> Hashes { get; set; }
        }
    }
}