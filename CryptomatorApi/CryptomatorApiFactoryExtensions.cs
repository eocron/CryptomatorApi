using CryptomatorApi.Core;

namespace CryptomatorApi;

public static class CryptomatorApiFactoryExtensions
{
    public static ICryptomatorApi Create(this ICryptomatorApiFactory factory, string password, string vaultPath)
    {
        return new LazyCryptomatorApi(ct => factory.Unlock(password, vaultPath, ct));
    }
}