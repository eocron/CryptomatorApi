using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

/// <summary>
///     The Aead class provides authenticated encryption with associated
///     data. This class provides a high-level interface to Miscreant's
///     misuse-resistant encryption.
/// </summary>
public sealed class Aead : IDisposable
{
    private readonly AesSiv _siv;
    private bool _disposed;

    private Aead(AesSiv siv)
    {
        _siv = siv;
    }

    /// <summary>
    ///     Disposes this object.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _siv.Dispose();
            _disposed = true;
        }
    }

    /// <summary>
    ///     Generates a random nonce.
    /// </summary>
    /// <param name="size">Nonce size in bytes.</param>
    /// <returns>Generated nonce.</returns>
    public static byte[] GenerateNonce(int size)
    {
        if (size < Constants.BlockSize) throw new CryptographicException("Nonce size is too small.");

        return Utils.GetRandomBytes(size);
    }

    /// <summary>
    ///     Generates a random 32-byte encryption key.
    /// </summary>
    /// <returns>Generated key.</returns>
    public static byte[] GenerateKey256()
    {
        return Utils.GetRandomBytes(Constants.AesSiv256KeySize);
    }

    /// <summary>
    ///     Generates a random 64-byte encryption key.
    /// </summary>
    /// <returns>Generated key.</returns>
    public static byte[] GenerateKey512()
    {
        return Utils.GetRandomBytes(Constants.AesSiv512KeySize);
    }

    /// <summary>
    ///     Initializes a new AEAD instance using the AES-CMAC-SIV algorithm.
    /// </summary>
    /// <param name="key">The secret key for AES-CMAC-SIV encryption.</param>
    /// <returns>An AEAD instance.</returns>
    public static Aead CreateAesCmacSiv(byte[] key)
    {
        return new Aead(AesSiv.CreateAesCmacSiv(key));
    }

    /// <summary>
    ///     Initializes a new AEAD instance using the AES-PMAC-SIV algorithm.
    /// </summary>
    /// <param name="key">The secret key for AES-PMAC-SIV encryption.</param>
    /// <returns>An AEAD instance.</returns>
    public static Aead CreateAesPmacSiv(byte[] key)
    {
        return new Aead(AesSiv.CreateAesPmacSiv(key));
    }

    /// <summary>
    ///     Seal encrypts and authenticates plaintext, authenticates
    ///     the associated data, and returns the result.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce">The nonce for encryption.</param>
    /// <param name="data">Associated data to authenticate.</param>
    /// <returns>Concatenation of the authentication tag and the encrypted data.</returns>
    public byte[] Seal(byte[] plaintext, byte[] nonce = null, byte[] data = null)
    {
        return _siv.Seal(plaintext, data, nonce);
    }

    /// <summary>
    ///     Open decrypts ciphertext, authenticates the decrypted plaintext
    ///     and the associated data and, if successful, returns the result.
    ///     In case of failed decryption, this method throws
    ///     <see cref="CryptographicException" />.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="nonce">The nonce for encryption.</param>
    /// <param name="data">Associated data to authenticate.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="CryptographicException">Thrown when the ciphertext is invalid.</exception>
    public byte[] Open(byte[] ciphertext, byte[] nonce = null, byte[] data = null)
    {
        return _siv.Open(ciphertext, data, nonce);
    }
}