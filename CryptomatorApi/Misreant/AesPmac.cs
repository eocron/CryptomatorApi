using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

/// <summary>
///     PMAC message authentication code, defined in the paper
///     <see href="http://web.cs.ucdavis.edu/~rogaway/ocb/pmac.pdf">
///         A Block-Cipher Mode of Operation for Parallelizable Message Authentication
///     </see>
///     .
/// </summary>
public sealed class AesPmac : IMac
{
    private const int BlockSize = Constants.BlockSize;
    private const int BufferSize = 4096;

    private readonly Aes _aes;
    private readonly byte[] _buffer = new byte[BufferSize];
    private readonly ICryptoTransform _encryptor;
    private readonly byte[] _inv;
    private readonly byte[][] _l = new byte[31][];
    private readonly byte[] _offset = new byte[BlockSize];
    private readonly byte[] _sum = new byte[BlockSize];
    private uint _counter;
    private bool _disposed;
    private int _position;

    /// <summary>
    ///     Initializes a new instance of the <see cref="AesPmac" /> class with the specified key.
    /// </summary>
    /// <param name="key">The secret key for <see cref="AesPmac" /> authentication.</param>
    public AesPmac(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));

        _aes = Utils.CreateAes(CipherMode.ECB);
        _encryptor = _aes.CreateEncryptor(key, null);

        var temp = new byte[BlockSize];
        _encryptor.TransformBlock(temp, 0, BlockSize, temp, 0);

        for (var i = 0; i < _l.Length; ++i)
        {
            _l[i] = (byte[])temp.Clone();
            Utils.Multiply(temp);
        }

        _inv = (byte[])_l[0].Clone();
        var lastBit = _inv[BlockSize - 1] & 1;

        for (var i = BlockSize - 1; i > 0; --i)
        {
            var carry = Subtle.ConstantTimeSelect(_inv[i - 1] & 1, 0x80, 0);
            _inv[i] = (byte)((_inv[i] >> 1) | carry);
        }

        _inv[0] >>= 1;
        _inv[0] ^= (byte)Subtle.ConstantTimeSelect(lastBit, 0x80, 0);
        _inv[BlockSize - 1] ^= (byte)Subtle.ConstantTimeSelect(lastBit, Constants.R >> 1, 0);
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
            ProcessBuffer(BlockSize);
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
            Array.Copy(seg.Array, seg.Offset, _buffer, _position, count);
            ProcessBuffer(count);
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
            Utils.Xor(_buffer, _sum, BlockSize);
            Utils.Xor(_inv, _sum, BlockSize);
        }
        else
        {
            Utils.Pad(_buffer, _position);
            Utils.Xor(_buffer, _sum, BlockSize);
        }

        var result = _encryptor.TransformFinalBlock(_sum, 0, BlockSize);

        Array.Clear(_offset, 0, BlockSize);
        Array.Clear(_sum, 0, BlockSize);

        _counter = 0;
        _position = 0;

        return result;
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
            Array.Clear(_offset, 0, BlockSize);
            Array.Clear(_sum, 0, BlockSize);

            _disposed = true;
        }
    }

    internal static IMac Create(byte[] key)
    {
        return new AesPmac(key);
    }

    private void ProcessBuffer(int size)
    {
        for (var i = 0; i < size; i += BlockSize)
        {
            var trailingZeros = Utils.TrailingZeros(_counter + 1);

            Utils.Xor(_l[trailingZeros], _offset, BlockSize);
            Utils.Xor(_offset, 0, _buffer, i, BlockSize);

            ++_counter;
        }

        _encryptor.TransformBlock(_buffer, 0, size, _buffer, 0);

        for (var i = 0; i < size; i += BlockSize) Utils.Xor(_buffer, i, _sum, 0, BlockSize);
    }
}