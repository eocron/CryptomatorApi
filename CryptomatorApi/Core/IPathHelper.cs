namespace CryptomatorApi.Core;

public interface IPathHelper
{
    string Combine(params string[] parts);
    string[] Split(string virtualPath);
    bool Equals(string path1, string path2);
}