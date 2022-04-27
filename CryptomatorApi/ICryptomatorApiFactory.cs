using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi;

public interface ICryptomatorApiFactory
{
    Task<ICryptomatorApi> Unlock(string password, string vaultPath, CancellationToken cancellationToken);
}