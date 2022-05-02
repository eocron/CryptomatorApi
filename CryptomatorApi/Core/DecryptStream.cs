using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core.Contract;

namespace CryptomatorApi.Core;

internal sealed class DecryptStream : Stream
{
    private const int EncryptionMetaSize = 48;
    private const int EncryptedBlockSize = UnencryptedBlockSize + EncryptionMetaSize;
    private const int UnencryptedBlockSize = 32768;
    private const int HeaderSize = 16 + 40 + 32;

    private readonly byte[] _buffer = new byte[EncryptedBlockSize];
    private readonly Stream _inner;
    private readonly Keys _keys;
    private long _blockNum;
    private byte[] _current;
    private int _currentPos;
    private Header _header;
    private long _pos;

    public DecryptStream(Stream inner, Keys keys)
    {
        _keys = keys;
        _inner = inner;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanWrite => false;
    public override long Length
    {
        get
        {
            var lengthWithoutHeader = _inner.Length - HeaderSize;
            var encryptedTailSize = lengthWithoutHeader % EncryptedBlockSize;
            var blockCount = lengthWithoutHeader / EncryptedBlockSize;

            var result = blockCount * UnencryptedBlockSize +
                         (encryptedTailSize == 0 ? 0 : (encryptedTailSize - EncryptionMetaSize));
            return result;
        }
    }

    public override long Position
    {
        get => _pos;
        set
        {
            if (CanSeek)
                Seek(value, SeekOrigin.Begin);
            else
            {
                throw new NotSupportedException();
            }
        }
    }

    public override void Flush()
    {
        _inner.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer, offset, count, CancellationToken.None).Result;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_header == null)
        {
            _header = await ReadHeader(cancellationToken).ConfigureAwait(false);
        }

        int i = 0;
        while (i < count)
        {
            if (_current == null || _currentPos >= _current.Length)
            {
                _current = await ReadBlock(cancellationToken).ConfigureAwait(false);
                _currentPos = 0;

                if (_current == null)
                    return i;
            }

            var toCopy = Math.Min(buffer.Length - i, _current.Length - _currentPos);
            Array.Copy(_current, _currentPos, buffer, i, toCopy);
            _pos += toCopy;
            i += toCopy;
            _currentPos += toCopy;
        }

        return count;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return SeekAsync(offset, origin, CancellationToken.None).GetAwaiter().GetResult();
    }

    private void CheckOffset(long offset)
    {
        if (offset < 0)
            throw new IOException("The parameter is incorrect.");
    }

    private async Task<long> SeekAsync(long offset, SeekOrigin origin, CancellationToken cancellationToken)
    {
        if (!CanSeek)
            throw new NotSupportedException();
        if (origin == SeekOrigin.Current)
        {
            offset = _pos + offset;
            origin = SeekOrigin.Begin;
        }
        else if (origin == SeekOrigin.End)
        {
            offset = Length + offset;
            origin = SeekOrigin.Begin;
        }
        CheckOffset(offset);

        if (_header == null)
        {
            _inner.Seek(0, SeekOrigin.Begin);
            _header = await ReadHeader(cancellationToken).ConfigureAwait(false);
        }

        var blockTailSize = offset % UnencryptedBlockSize;
        var blockCount = offset / UnencryptedBlockSize;


        var encryptedFullBlockOffset = HeaderSize + blockCount * EncryptedBlockSize;
        _inner.Seek(encryptedFullBlockOffset, origin);
        _blockNum = blockCount;
        _current = await ReadBlock(cancellationToken).ConfigureAwait(false);
        _currentPos = (int)blockTailSize;
        _pos = offset;
        return _pos;
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    public override void Close()
    {
        _inner.Close();
        base.Close();
    }

    private async Task<byte[]> ReadBlock(CancellationToken cancellationToken)
    {
        var chunk = new FixedSpan(_buffer);
        int tmpRead = await ReadExactly(_inner, chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);
        if (tmpRead == 0)
            return null;

        var block = new Block(chunk, 0, tmpRead);

        var beBlockNum = BitConverter.GetBytes(_blockNum);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(beBlockNum);

        _header.ChunkHmac.Initialize();
        _header.ChunkHmac.Update(new FixedSpan(_header.HeaderNonce));
        _header.ChunkHmac.Update(new FixedSpan(beBlockNum));
        _header.ChunkHmac.Update(block.Nonce);
        _header.ChunkHmac.DoFinal(block.Payload);
        if (!HashEquals(_header.ChunkHmac.Hash, block.Mac))
            throw new IOException("Encrypted file fails integrity check.");

        var result = AesCtr(block.Payload, _header.ContentKey, block.Nonce);
        _blockNum++;
        return result;
    }

    private static async Task<int> ReadExactly(Stream stream, FixedSpan buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        int read;
        while (count > 0 && (read = await stream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false)) > 0)
        {
            count -= read;
            offset += read;
            totalRead += read;
        }

        return totalRead;
    }

    private async Task<Header> ReadHeader(CancellationToken cancellationToken)
    {
        var chunk = new FixedSpan(_buffer, 0, HeaderSize);
        if (await _inner.ReadAsync(chunk, cancellationToken).ConfigureAwait(false) != HeaderSize)
            throw new IOException("Invalid file header.");

        var block = new Block(chunk, 0, HeaderSize);

        var headerHmac = new Hmac(_keys.MacKey);
        headerHmac.Update(block.Nonce);
        headerHmac.DoFinal(block.Payload);
        if (!HashEquals(headerHmac.Hash, block.Mac))
            throw new IOException("Encrypted file fails integrity check.");

        var cleartextPayload = AesCtr(block.Payload, _keys.MasterKey, block.Nonce);
        var contentKey = new FixedSpan(cleartextPayload, 8, 32);

        return new Header(contentKey, headerHmac, block.Nonce);
    }

    private static bool HashEquals(byte[] a1, FixedSpan a2)
    {
        if (a1.Length != a2.Length) return false;

        for (var i = 0; i < a1.Length; i++)
            if (a1[i] != a2[i])
                return false;

        return true;
    }

    private static byte[] AesCtr(FixedSpan input, byte[] key, FixedSpan ivSpan)
    {
        var iv = ivSpan.ToArray(); //use a copy to avoid updating original IV.

        //Since we're always decrypting an in-memory chunk we don't bother with streams
        using var aesAlg = new Aes128CounterModeSymmetricAlgorithm(iv);
        using var decryptor = aesAlg.CreateDecryptor(key, iv);
        return decryptor.TransformFinalBlock(input);
    }

    private readonly struct Block
    {
        public readonly FixedSpan Nonce;
        public readonly FixedSpan Payload;
        public readonly FixedSpan Mac;

        public Block(FixedSpan buffer, int offset, int length)
        {
            Nonce = buffer.Slice(offset, 16);
            Payload = buffer.Slice(offset + Nonce.Length, length - 48);
            Mac = buffer.Slice(offset + Nonce.Length + Payload.Length, 32);
        }
    }

    private sealed class Header
    {
        public readonly Hmac ChunkHmac;
        public readonly byte[] ContentKey;
        public readonly byte[] HeaderNonce;

        public Header(FixedSpan contentKey, Hmac chunkHmac, FixedSpan headerNonce)
        {
            ContentKey = contentKey.ToArray();
            ChunkHmac = chunkHmac;
            HeaderNonce = headerNonce.ToArray();
        }
    }

    private sealed class Hmac : HMACSHA256
    {
        public Hmac(byte[] key) : base(key)
        {
        }

        public void Update(FixedSpan input)
        {
            this.TransformBlock(input);
        }

        public void DoFinal(FixedSpan input)
        {
            this.TransformFinalBlock(input);
        }
    }
}