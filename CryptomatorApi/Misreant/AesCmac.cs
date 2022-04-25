using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

/// <summary>
///     CMAC message authentication code, defined in NIST Special Publication
///     <see href="https://csrc.nist.gov/publications/detail/sp/800-38b/archive/2005-05-01">SP 800-38B</see>.
/// </summary>
public sealed class AesCmac : IMac
{
    private const int BlockSize = Constants.BlockSize;
    private const int BufferSize = 4096;
    private static readonly byte[] Zero = new byte[BlockSize];

    private readonly Aes _aes;
    private readonly byte[] _buffer = new byte[BufferSize];
    private readonly ICryptoTransform _encryptor;
    private readonly byte[] _k1 = new byte[BlockSize];
    private readonly byte[] _k2 = new byte[BlockSize];
    private bool _disposed;
    private int _position;

    /// <summary>
    ///     Initializes a new instance of the <see cref="AesCmac" /> class with the specified key.
    /// </summary>
    /// <param name="key">The secret key for <see cref="AesCmac" /> authentication.</param>
    public AesCmac(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));

        using (var aes = Utils.CreateAes(CipherMode.ECB))
        using (var encryptor = aes.CreateEncryptor(key, null))
        {
            encryptor.TransformBlock(Zero, 0, BlockSize, _k1, 0);
            Utils.Multiply(_k1);

            Array.Copy(_k1, _k2, BlockSize);
            Utils.Multiply(_k2);
        }

        _aes = Utils.CreateAes(CipherMode.CBC);
        _encryptor = _aes.CreateEncryptor(key, Zero);
    }

    /// <summary>
    ///     Adds more data to the running hash.
    /// </summary>
    /// <param name="input">The input to hash.</param>
    /// <param name="index">The offset into the input byte array from which to begin using data.</param>
    /// <param name="size">The number of bytes in the input byte array to use as data.</param>
    public void HashCore(byte[] input, int index, int size)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(AesCmac));

        var seg = new ArraySegment<byte>(input, index, size);
        var left = BlockSize - _position;

        if (_position > 0 && seg.Count > left)
        {
            Array.Copy(seg.Array, seg.Offset, _buffer, _position, left);
            _encryptor.TransformBlock(_buffer, 0, BlockSize, _buffer, 0);
            seg = seg.Slice(left);
            _position = 0;
        }

        while (seg.Count > BlockSize)
        {
            // Encrypting single block in .NET is extremely slow, so we want
            // to encrypt as much of the input as possible in a single call to
            // TransformBlock. TransformBlock expects valid output buffer, so
            // we pre-allocate 4KB buffer for this purpose.

            var count = Math.Min(BufferSize, (seg.Count - 1) / BlockSize * BlockSize);
            _encryptor.TransformBlock(seg.Array, seg.Offset, count, _buffer, 0);
            seg = seg.Slice(count);
        }

        if (seg.Count > 0)
        {
            Array.Copy(seg.Array, seg.Offset, _buffer, _position, seg.Count);
            _position += seg.Count;
        }
    }

    /// <summary>
    ///     Returns the current hash and resets the hash state.
    /// </summary>
    /// <returns>The value of the computed hash.</returns>
    public byte[] HashFinal()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(AesCmac));

        if (_position == BlockSize)
        {
            Utils.Xor(_k1, _buffer, BlockSize);
        }
        else
        {
            Utils.Pad(_buffer, _position);
            Utils.Xor(_k2, _buffer, BlockSize);
        }

        _position = 0;

        return _encryptor.TransformFinalBlock(_buffer, 0, BlockSize);
    }

    /// <summary>
    ///     Disposes this object.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _aes.Dispose();
            _encryptor.Dispose();

            Array.Clear(_buffer, 0, BufferSize);
            Array.Clear(_k1, 0, BlockSize);
            Array.Clear(_k2, 0, BlockSize);

            _disposed = true;
        }
    }

    internal static IMac Create(byte[] key)
    {
        return new AesCmac(key);
    }
}