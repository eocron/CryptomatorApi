﻿using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;
using CryptomatorApi.Core.Contract;
using CryptSharp.Core.Utility;
using Newtonsoft.Json;
using RFC3394;

namespace CryptomatorApi;

public sealed class CryptomatorApiFactory
{
    private readonly IFileProvider _fileProvider;

    public CryptomatorApiFactory(IFileProvider fileProvider)
    {
        _fileProvider = fileProvider;
    }

    public ICryptomatorApi Create(string password, string vaultPath)
    {
        return new LazyCryptomatorApi(ct => CreateAsync(password, vaultPath, ct));
    }

    private async Task<ICryptomatorApi> CreateAsync(string password, string vaultPath, CancellationToken cancellationToken)
    {
        var masterKeyPath = "";
        VaultConfig vaultConfig = null;

        var vaultConfigPath = Path.Combine(vaultPath, "vault.cryptomator");
        if (await _fileProvider.IsFileExistsAsync(vaultConfigPath, cancellationToken).ConfigureAwait(false))
        {
            vaultConfig = await LoadVaultConfig(vaultConfigPath, false, null, cancellationToken).ConfigureAwait(false);
            var kidParts = vaultConfig.VcH.Kid.Split(':');
            if (kidParts.Length != 2 || kidParts[0] != "masterkeyfile")
                throw new Exception($"vault config id parameter unsupported : {vaultConfig.VcH.Kid}");
            masterKeyPath = Path.Combine(vaultPath, kidParts[1]);
        }
        else
        {
            masterKeyPath = Path.Combine(vaultPath, "masterkey.cryptomator");
        }

        if (!await _fileProvider.IsFileExistsAsync(masterKeyPath, cancellationToken).ConfigureAwait(false))
            throw new FileNotFoundException("Missing master key file (masterkey.cryptomator)");

        var jsonString = await _fileProvider.ReadAllTextAsync(masterKeyPath, cancellationToken).ConfigureAwait(false);
        var mkey = JsonConvert.DeserializeObject<MasterKey>(jsonString);

        var abPrimaryMasterKey = Convert.FromBase64String(mkey.PrimaryMasterKey);
        var abHmacMasterKey = Convert.FromBase64String(mkey.HmacMasterKey);
        var abScryptSalt = Convert.FromBase64String(mkey.ScryptSalt);

        var kek = SCrypt.ComputeDerivedKey(Encoding.ASCII.GetBytes(password), abScryptSalt, mkey.ScryptCostParam,
            mkey.ScryptBlockSize, 1, 1, 32);
        using var rfc = new RFC3394Algorithm();

        var keys = new Keys();
        keys.MasterKey = rfc.Unwrap(kek, abPrimaryMasterKey);
        keys.MacKey = rfc.Unwrap(kek, abHmacMasterKey);
        keys.SivKey = keys.MacKey.Concat(keys.MasterKey).ToArray();
        var jwtKey = keys.MasterKey.Concat(keys.MacKey).ToArray();

        //Validate vault config if present
        if (vaultConfig != null)
            //Reload the vault config, this time verifying the signature
            vaultConfig = await LoadVaultConfig(vaultConfigPath, true, jwtKey, cancellationToken).ConfigureAwait(false);

        if (mkey.Version == 6) return new V6CryptomatorApi(keys, vaultPath, _fileProvider);

        if (mkey.Version == 7) return new V7CryptomatorApi(keys, vaultPath, _fileProvider);

        if (mkey.Version == 999)
        {
            //version must come from vault.cryptomator.  If v8, can handle as if version 7 
            //because there are no structural changes.
            if (vaultConfig == null)
                throw new Exception("Missing required vault configuration");
            if (vaultConfig.VcD.Format == 8)
                return new V7CryptomatorApi(keys, vaultPath, _fileProvider);
            throw new Exception(
                $"Only format 8 vaults are currently support. Vault format is {vaultConfig.VcD.Format}");
        }

        throw new ArgumentException($"Vault version {mkey.Version} is unsupported");
    }


    private async Task<VaultConfig> LoadVaultConfig(string vaultConfigPath, bool verify, byte[] key,
        CancellationToken cancellationToken)
    {
        try
        {
            var token = await _fileProvider.ReadAllTextAsync(vaultConfigPath, cancellationToken).ConfigureAwait(false);
            var vaultConfig = GetVaultConfigFromJwt(token, verify, key);
            return vaultConfig;
        }
        catch (Exception ex)
        {
            throw new Exception("Cannot load vault configuration", ex);
        }
    }

    public static VaultConfig GetVaultConfigFromJwt(string token, bool verify = false, byte[] key = null)
    {
        try
        {
            var parts = token.Split('.');

            if (parts.Length != 3)
                throw new Exception("Vault configuration JWT is invalid");

            var header = parts[0];
            var payload = parts[1];
            var jwtSignature = parts[2];

            var headerJson = Base64Url.DecodeToString(header);
            var vaultConfigHeader = JsonConvert.DeserializeObject<VaultConfigHeader>(headerJson);
            var payloadJson = Base64Url.DecodeToString(payload);
            var vaultConfigData = JsonConvert.DeserializeObject<VaultConfigData>(payloadJson);

            if (verify)
            {
                HMAC hmac;
                switch (vaultConfigHeader.Alg)
                {
                    case "HS256":
                        hmac = new HMACSHA256();
                        break;
                    case "HS384":
                        hmac = new HMACSHA384();
                        break;
                    case "HS512":
                        hmac = new HMACSHA512();
                        break;
                    default:
                        throw new Exception("Unsupported vault configuration signature algorithm");
                }

                hmac.Key = key;
                var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
                var signature = hmac.ComputeHash(bytesToSign);
                var computedJwtSignature = Base64Url.Encode(signature);
                if (jwtSignature != computedJwtSignature)
                    throw new Exception("Vault signature is invalid");
            }

            var vaultConfig = new VaultConfig();
            vaultConfig.VcH = vaultConfigHeader;
            vaultConfig.VcD = vaultConfigData;
            return vaultConfig;
        }
        catch (Exception ex)
        {
            throw new Exception("Vault configuration invalid or unsupported", ex);
        }
    }
}