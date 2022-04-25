namespace CryptomatorApi.Core.Contract;

public class VaultConfigData
{
    public int Format { get; set; }
    public int ShorteningThreshold { get; set; }
    public string Jti { get; set; }
    public string CipherCombo { get; set; }
}