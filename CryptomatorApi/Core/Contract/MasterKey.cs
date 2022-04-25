namespace CryptomatorApi.Core.Contract;

public class MasterKey
{
    public string ScryptSalt { get; set; }
    public int ScryptCostParam { get; set; }
    public int ScryptBlockSize { get; set; }
    public string PrimaryMasterKey { get; set; }
    public string HmacMasterKey { get; set; }
    public string VersionMac { get; set; }
    public int Version { get; set; }
}