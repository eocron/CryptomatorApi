using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

/// <summary>
///     AES-SIV authenticated encryption mode, defined in
///     <see href="https://tools.ietf.org/html/rfc5297">RFC 5297</see>.
/// </summary>
public sealed class AesSiv : IDisposable
{
    private const int BlockSize = Constants.BlockSize;
    private const int MaxAssociatedDataItems = 126;

    private static readonly byte[] Empty = Array.Empty<byte>();
    private static readonly byte[] Zero = new byte[BlockSize];
    private readonly AesCtr _ctr;

    private readonly IMac _mac;
    private bool _disposed;

    private AesSiv(Func<byte[], IMac> macFactory, byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));

        if (key.Length != Constants.AesSiv256KeySize && key.Length != Constants.AesSiv512KeySize)
            throw new CryptographicException("Specified key is not a valid size for this algorithm.");

        var halfKeySize = key.Length / 2;

        var k1 = new byte[halfKeySize];
        var k2 = new byte[halfKeySize];

        Array.Copy(key, 0, k1, 0, halfKeySize);
        Array.Copy(key, halfKeySize, k2, 0, halfKeySize);

        _mac = macFactory(k1);
        _ctr = new AesCtr(k2);
    }

    /// <summary>
    ///     Disposes this object.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _mac.Dispose();
            _ctr.Dispose();

            _disposed = true;
        }
    }

    /// <summary>
    ///     Initializes a new instance of the AES-CMAC-SIV algorithm with the specified key.
    /// </summary>
    /// <param name="key">The secret key for AES-CMAC-SIV encryption.</param>
    /// <returns>An AES-CMAC-SIV instance.</returns>
    public static AesSiv CreateAesCmacSiv(byte[] key)
    {
        return new AesSiv(AesCmac.Create, key);
    }

    /// <summary>
    ///     Seal encrypts and authenticates plaintext, authenticates the given
    ///     associated data items, and returns the result. For nonce-based
    ///     encryption, the nonce should be the last associated data item.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="data">Associated data items to authenticate.</param>
    /// <returns>Concatenation of the authentication tag and the encrypted data.</returns>
    public byte[] Seal(byte[] plaintext, params byte[][] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        if (data.Length > MaxAssociatedDataItems)
            throw new CryptographicException($"Maximum number of associated data items is {MaxAssociatedDataItems}");

        if (plaintext == null) plaintext = Empty;

        var iv = S2V(data, plaintext);
        var output = new byte[iv.Length + plaintext.Length];

        Array.Copy(iv, output, iv.Length);
        ZeroIvBits(iv);

        _ctr.Reset(iv);
        _ctr.Encrypt(plaintext, 0, plaintext.Length, output, iv.Length);

        return output;
    }

    /// <summary>
    ///     Open decrypts ciphertext, authenticates the decrypted plaintext
    ///     and the given associated data items and, if successful, returns
    ///     the result. For nonce-based encryption, the nonce should be the
    ///     last associated data item. In case of failed decryption, this
    ///     method throws <see cref="CryptographicException" />.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="data">Associated data items to authenticate.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="CryptographicException">Thrown when the ciphertext is invalid.</exception>
    public byte[] Open(byte[] ciphertext, params byte[][] data)
    {
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));

        if (data == null) throw new ArgumentNullException(nameof(data));

        if (ciphertext.Length < BlockSize) throw new CryptographicException("Malformed or corrupt ciphertext.");

        if (data.Length > MaxAssociatedDataItems)
            throw new CryptographicException($"Maximum number of associated data items is {MaxAssociatedDataItems}");

        var iv = new byte[BlockSize];
        var output = new byte[ciphertext.Length - iv.Length];

        Array.Copy(ciphertext, 0, iv, 0, BlockSize);
        ZeroIvBits(iv);

        _ctr.Reset(iv);
        _ctr.Encrypt(ciphertext, BlockSize, output.Length, output, 0);

        var v = S2V(data, output);

        if (!Subtle.ConstantTimeEquals(ciphertext, v, BlockSize))
            throw new CryptographicException("Malformed or corrupt ciphertext.");

        return output;
    }

    /// <summary>
    ///     S2V operation, defined in the section 2.4 of
    ///     <see href="https://tools.ietf.org/html/rfc5297#section-2.4">RFC 5297</see>.
    /// </summary>
    private byte[] S2V(byte[][] headers, byte[] message)
    {
        if (headers == null) throw new ArgumentNullException(nameof(headers));

        if (message == null) throw new ArgumentNullException(nameof(message));

        // The standalone S2V returns CMAC(1) if the number of
        // passed vectors is zero, however in SIV contruction
        // this case is never triggered, since we always pass
        // plaintext as the last vector (even if it's zero-length),
        // so we omit this case.

        _mac.HashCore(Zero, 0, BlockSize);
        var v = _mac.HashFinal();

        foreach (var header in headers)
        {
            if (header == null) continue;

            _mac.HashCore(header, 0, header.Length);
            Utils.Multiply(v);
            Utils.Xor(_mac.HashFinal(), v, BlockSize);
        }

        if (message.Length >= BlockSize)
        {
            var n = message.Length - BlockSize;

            _mac.HashCore(message, 0, n);
            Utils.Xor(message, n, v, 0, BlockSize);
            _mac.HashCore(v, 0, BlockSize);

            return _mac.HashFinal();
        }

        var padded = new byte[BlockSize];

        Array.Copy(message, padded, message.Length);
        Utils.Multiply(v);
        Utils.Pad(padded, message.Length);
        Utils.Xor(padded, v, BlockSize);
        _mac.HashCore(v, 0, BlockSize);

        return _mac.HashFinal();
    }

    private void ZeroIvBits(byte[] iv)
    {
        iv[^8] &= 0x7f;
        iv[^4] &= 0x7f;
    }
}