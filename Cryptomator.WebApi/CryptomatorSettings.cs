namespace Cryptomator.WebApi;

public class CryptomatorSettings
{
    public string Password { get; set; }
    public S3Settings S3 { get; set; }
    public string VaultPath { get; set; }
}


public class S3Settings
{
    public string BucketName { get; set; }
    public string AccessKey { get; set; }
    public string SecretKey { get; set; }
    public string Endpoint { get; set; }
}