namespace CryptomatorApi.Core.Contract;

internal sealed class VaultConfigHeader
{
    public string Kid { get; set; }
    public string Typ { get; set; }
    public string Alg { get; set; }
}