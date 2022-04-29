using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

/// <summary>
///     Counter (CTR) mode, defined in NIST Special Publication
///     <see href="https://csrc.nist.gov/publications/detail/sp/800-38a/final">SP 800-38A</see>.
/// </summary>
internal sealed class AesCtr : IDisposable
{
    private const int BlockSize = Constants.BlockSize;
    private const int KeyStreamBufferSize = 4096;

    private readonly Aes _aes;
    private readonly ICryptoTransform _encryptor;
    private byte[] _counter;
    private bool _disposed;
    private ArraySegment<byte> _keyStream;

    /// <summary>
    ///     Initializes a new instance of the <see cref="AesCtr" /> class with the
    ///     specified key. For internal use only. The initialization vector will
    ///     be set later by the <see cref="AesSiv" /> object.
    /// </summary>
    /// <param name="key">The secret key for <see cref="AesCtr" /> encryption.</param>
    internal AesCtr(byte[] key)
    {
        _aes = Aes.Create();
        _aes.Mode = CipherMode.ECB;

        _encryptor = _aes.CreateEncryptor(key, null);

        var buffer = new byte[KeyStreamBufferSize];
        _keyStream = new ArraySegment<byte>(buffer, 0, 0);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _aes.Dispose();
            _encryptor.Dispose();

            Array.Clear(_counter, 0, BlockSize);
            Array.Clear(_keyStream.Array, 0, KeyStreamBufferSize);

            _disposed = true;
        }
    }

    /// <summary>
    ///     Encrypt/decrypt the input by xoring it with the CTR keystream.
    /// </summary>
    /// <param name="input">The input to encrypt.</param>
    /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
    /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
    /// <param name="output">The output to which to write the encrypted data.</param>
    /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
    public void Encrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(AesCtr));

        var inputSeg = new ArraySegment<byte>(input, inputOffset, inputCount);
        var outputSeg = new ArraySegment<byte>(output, outputOffset, inputCount);

        while (inputSeg.Count > 0)
        {
            if (_keyStream.Count == 0) GenerateKeyStream(inputSeg.Count);

            var count = Math.Min(inputSeg.Count, _keyStream.Count);
            var keyStreamPosition = _keyStream.Offset;
            var inputPosition = inputSeg.Offset;
            var outputPosition = outputSeg.Offset;

            for (var i = 0; i < count; ++i)
            {
                var c = (byte)(_keyStream.Array[keyStreamPosition + i] ^ input[inputPosition + i]);
                output[outputPosition + i] = c;
            }

            _keyStream = _keyStream.Slice(count);
            inputSeg = inputSeg.Slice(count);
            outputSeg = outputSeg.Slice(count);
        }
    }

    /// <summary>
    ///     Reset the initialization vector. For internal use only. This
    ///     method is needed in order to avoid creating heavyweight
    ///     <see cref="AesCtr" /> object every time we call
    ///     <see cref="AesSiv.Seal" /> or <see cref="AesSiv.Open" /> methods.
    /// </summary>
    /// <param name="iv">The initialization vector for <see cref="AesCtr" /> encryption.</param>
    internal void Reset(byte[] iv)
    {
        _counter = iv;
        _keyStream = new ArraySegment<byte>(_keyStream.Array, 0, 0);
    }

    private void GenerateKeyStream(int inputCount)
    {
        var size = Math.Min(KeyStreamBufferSize, Utils.Ceil(inputCount, BlockSize) * BlockSize);
        var array = _keyStream.Array;

        for (var i = 0; i < size; i += BlockSize)
        {
            Array.Copy(_counter, 0, array, i, BlockSize);
            IncrementCounter();
        }

        _encryptor.TransformBlock(array, 0, size, array, 0);
        _keyStream = new ArraySegment<byte>(array, 0, size);
    }

    private void IncrementCounter()
    {
        for (var i = BlockSize - 1; i >= 0; --i)
            if (++_counter[i] != 0)
                break;
    }
}