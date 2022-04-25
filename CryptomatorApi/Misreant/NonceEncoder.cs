using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

internal class NonceEncoder
{
    private const int NonceSize = Constants.StreamNonceSize;

    private readonly byte[] _nonce;
    private uint _counter;

    public NonceEncoder(byte[] nonce)
    {
        if (nonce == null) throw new ArgumentNullException(nameof(nonce));

        if (nonce.Length != NonceSize)
            throw new CryptographicException("Specified nonce does not match the nonce size for this algorithm.");

        _nonce = new byte[NonceSize + Constants.StreamCounterSize + 1];
        Array.Copy(nonce, _nonce, NonceSize);
    }

    public byte[] Next(bool last)
    {
        _nonce[NonceSize] = (byte)((_counter >> 24) & 0xff);
        _nonce[NonceSize + 1] = (byte)((_counter >> 16) & 0xff);
        _nonce[NonceSize + 2] = (byte)((_counter >> 8) & 0xff);
        _nonce[NonceSize + 3] = (byte)(_counter & 0xff);

        if (last) _nonce[_nonce.Length - 1] = 1;

        try
        {
            checked
            {
                ++_counter;
            }
        }
        catch (OverflowException ex)
        {
            throw new CryptographicException("STREAM counter overflowed.", ex);
        }

        return _nonce;
    }
}