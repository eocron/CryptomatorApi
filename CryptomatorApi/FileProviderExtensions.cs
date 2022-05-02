using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Providers;

namespace CryptomatorApi
{
    public static class FileProviderExtensions
    {
        public static async Task<string> ReadAllTextAsync(this IFileProvider fileProvider, string filePath,
            CancellationToken cancellationToken)
        {
            await using var s = await fileProvider.OpenReadAsync(filePath, cancellationToken).ConfigureAwait(false);
            using var sr = new StreamReader(s);
            return await sr.ReadToEndAsync().ConfigureAwait(false);

        }

        public static async Task<string[]> ReadAllLinesAsync(this IFileProvider fileProvider, string filePath,
            CancellationToken cancellationToken)
        {
            var text = await ReadAllTextAsync(fileProvider, filePath, cancellationToken).ConfigureAwait(false);
            return text?.Split(Environment.NewLine);
        }
    }
}
