using System;
using System.Linq;

namespace CryptomatorApi.Core;

public interface IPathHelper
{
    string Combine(params string[] parts);
    string[] Split(string virtualPath);
    bool Equals(string path1, string path2);
}

public sealed class PathHelper : IPathHelper
{
    private readonly char _pathSeparatorChar;

    public PathHelper(char pathSeparator)
    {
        _pathSeparatorChar = pathSeparator;
    }

    public bool Equals(string path1, string path2)
    {
        return string.Equals(path1, path2, StringComparison.OrdinalIgnoreCase);
    }
    public string Combine(params string[] parts)
    {
        return string.Join(_pathSeparatorChar,
            parts.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim(_pathSeparatorChar)));
    }

    public string[] Split(string virtualPath)
    {
        return virtualPath.Split(_pathSeparatorChar, StringSplitOptions.RemoveEmptyEntries);
    }
}