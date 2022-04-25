namespace CryptomatorApi;

public class FolderInfo
{
    public string Name { get; internal set; }
    public string VirtualPath { get; internal set; }
    public bool HasChildren { get; internal set; }
}