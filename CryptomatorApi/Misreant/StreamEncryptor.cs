using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

/// <summary>
///     STREAM online authenticated encryption, defined in the paper
///     <see href="https://eprint.iacr.org/2015/189.pdf">
///         Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
///     </see>
///     .
/// </summary>
public sealed class StreamEncryptor : IDisposable
{
    private readonly NonceEncoder _nonce;
    private readonly AesSiv _siv;
    private bool _disposed;
    private bool _finished;

    private StreamEncryptor(AesSiv siv, byte[] nonce)
    {
        _siv = siv;
        _nonce = new NonceEncoder(nonce);
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
    ///     Generates a random 8-byte STREAM nonce.
    /// </summary>
    /// <returns>Generated nonce.</returns>
    public static byte[] GenerateNonce()
    {
        return Utils.GetRandomBytes(Constants.StreamNonceSize);
    }

    /// <summary>
    ///     Initializes a new instance of the STREAM encryptor using the AES-CMAC-SIV algorithm.
    /// </summary>
    /// <param name="key">The secret key for encryption.</param>
    /// <param name="nonce">The nonce for encryption.</param>
    /// <returns>A STREAM encryptor instance.</returns>
    public static StreamEncryptor CreateAesCmacSivEncryptor(byte[] key, byte[] nonce)
    {
        var siv = AesSiv.CreateAesCmacSiv(key);
        return new StreamEncryptor(siv, nonce);
    }

    /// <summary>
    ///     Initializes a new instance of the STREAM encryptor using the AES-PMAC-SIV algorithm.
    /// </summary>
    /// <param name="key">The secret key for encryption.</param>
    /// <param name="nonce">The nonce for encryption.</param>
    /// <returns>A STREAM encryptor instance.</returns>
    public static StreamEncryptor CreateAesPmacSivEncryptor(byte[] key, byte[] nonce)
    {
        var siv = AesSiv.CreateAesPmacSiv(key);
        return new StreamEncryptor(siv, nonce);
    }

    /// <summary>
    ///     Seal encrypts and authenticates the next message in the STREAM,
    ///     authenticates the associated data, and returns the result.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="data">Associated data items to authenticate.</param>
    /// <param name="last">True if this is the last block in the STREAM.</param>
    /// <returns>Concatenation of the authentication tag and the encrypted data.</returns>
    public byte[] Seal(byte[] plaintext, byte[] data = null, bool last = false)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(StreamEncryptor));

        if (_finished) throw new CryptographicException("STREAM is already finished.");

        _finished = last;

        return _siv.Seal(plaintext, data, _nonce.Next(last));
    }
}