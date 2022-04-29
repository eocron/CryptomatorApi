using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;

namespace CryptomatorApi
{
    public static class CryptomatorApiExtensions
    {
        public static async IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfos(
            this ICryptomatorApi api,
            string folderPath = default,
            string searchPattern = default,
            SearchOption searchOption = SearchOption.TopDirectoryOnly,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var wildcard = (searchPattern == null || searchPattern == "*") ? null : new Wildcard(searchPattern);
            var stack = new Stack<string>();
            stack.Push(folderPath);
            while (stack.Count > 0)
            {
                var iterPath = stack.Pop();
                await foreach (var item in api.GetFileSystemInfos(iterPath, cancellationToken).ConfigureAwait(false))
                {
                    if (wildcard == null || wildcard.IsMatch(item.Name))
                    {
                        yield return item;
                    }

                    if (searchOption == SearchOption.AllDirectories && item is CryptomatorDirectoryInfo)
                    {
                        stack.Push(item.FullName);
                    }
                }
            }
        }
        public static async IAsyncEnumerable<CryptomatorFileInfo> GetFiles(
            this ICryptomatorApi api,
            string folderPath = default,
            string searchPattern = default,
            SearchOption searchOption = SearchOption.TopDirectoryOnly,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var wildcard = (searchPattern == null || searchPattern == "*") ? null : new Wildcard(searchPattern);
            if (searchOption == SearchOption.TopDirectoryOnly)
            {
                await foreach (var item in api.GetFiles(folderPath, cancellationToken).ConfigureAwait(false))
                {
                    if (wildcard == null || wildcard.IsMatch(item.Name))
                    {
                        yield return item;
                    }
                }
                yield break;
            }

            var stack = new Stack<string>();
            stack.Push(folderPath);
            while (stack.Count > 0)
            {
                var iterPath = stack.Pop();
                await foreach (var item in api.GetFileSystemInfos(iterPath, cancellationToken).ConfigureAwait(false))
                {
                    if (item is CryptomatorFileInfo file)
                    {
                        if (wildcard == null || wildcard.IsMatch(file.Name))
                        {
                            yield return file;
                        }
                    }
                    else
                    {
                        stack.Push(item.FullName);
                    }
                }
            }
        }
        public static async IAsyncEnumerable<CryptomatorDirectoryInfo> GetDirectories(
            this ICryptomatorApi api,
            string folderPath = default,
            string searchPattern = default,
            SearchOption searchOption = SearchOption.TopDirectoryOnly,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var wildcard = (searchPattern == null || searchPattern == "*") ? null : new Wildcard(searchPattern);
            if (searchOption == SearchOption.TopDirectoryOnly)
            {
                await foreach (var item in api.GetDirectories(folderPath, cancellationToken).ConfigureAwait(false))
                {
                    if (wildcard == null || wildcard.IsMatch(item.Name))
                    {
                        yield return item;
                    }
                }
                yield break;
            }

            var stack = new Stack<string>();
            stack.Push(folderPath);
            while (stack.Count > 0)
            {
                var iterPath = stack.Pop();
                await foreach (var item in api.GetFileSystemInfos(iterPath, cancellationToken).ConfigureAwait(false))
                {
                    if (item is CryptomatorDirectoryInfo dir && (wildcard == null || wildcard.IsMatch(dir.Name)))
                    {
                        yield return dir;
                        stack.Push(dir.FullName);
                    }
                }
            }
        }
    }
}
