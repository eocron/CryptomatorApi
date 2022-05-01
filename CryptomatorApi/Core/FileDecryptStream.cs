using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core.Contract;

namespace CryptomatorApi.Core;

internal sealed class FileDecryptStream : Stream
{
    private readonly byte[] _buffer = new byte[32768 + 48];
    private readonly Stream _inner;
    private readonly Keys _keys;
    private int _blockNum;
    private byte[] _current;
    private int _currentPos;
    private Header _header;
    private long _pos;

    public FileDecryptStream(Stream inner, Keys keys)
    {
        _keys = keys;
        _inner = inner;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _pos;
        set => throw new NotSupportedException();
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
            _current = await ReadBlock(cancellationToken).ConfigureAwait(false);
            _currentPos = 0;
        }

        if (_current == null)
            return 0;

        for (var i = 0; i < count; i++)
        {
            if (_currentPos == _current.Length)
            {
                _currentPos = 0;
                _current = await ReadBlock(cancellationToken).ConfigureAwait(false);
                if (_current == null)
                    return i;
            }

            buffer[i] = _current[_currentPos++];
            _pos++;
        }

        return count;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotImplementedException();
    }

    public override void SetLength(long value)
    {
        throw new NotImplementedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotImplementedException();
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

        var chunkHeader = new HeaderRaw(chunk, 0, tmpRead);

        var beBlockNum = BitConverter.GetBytes((long)_blockNum);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(beBlockNum);

        _header.ChunkHmac.Initialize();
        _header.ChunkHmac.Update(new FixedSpan(_header.HeaderNonce));
        _header.ChunkHmac.Update(new FixedSpan(beBlockNum));
        _header.ChunkHmac.Update(chunkHeader.Nonce);
        _header.ChunkHmac.DoFinal(chunkHeader.Payload);
        if (!HashEquals(_header.ChunkHmac.Hash, chunkHeader.Mac))
            throw new IOException("Encrypted file fails integrity check.");

        var result = AesCtr(chunkHeader.Payload, _header.ContentKey, chunkHeader.Nonce);
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
        const int headerSize = 16 + 40 + 32;
        var chunk = new FixedSpan(_buffer, 0, headerSize);
        if (await _inner.ReadAsync(chunk, cancellationToken).ConfigureAwait(false) != headerSize)
            throw new IOException("Invalid file header.");

        var chunkHeader = new HeaderRaw(chunk, 0, headerSize);

        var headerHmac = new Hmac(_keys.MacKey);
        headerHmac.Update(chunkHeader.Nonce);
        headerHmac.DoFinal(chunkHeader.Payload);
        if (!HashEquals(headerHmac.Hash, chunkHeader.Mac))
            throw new IOException("Encrypted file fails integrity check.");

        var cleartextPayload = AesCtr(chunkHeader.Payload, _keys.MasterKey, chunkHeader.Nonce);
        var contentKey = new FixedSpan(cleartextPayload, 8, 32);

        return new Header(contentKey, new Hmac(_keys.MacKey), chunkHeader.Nonce);
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
        var decryptor = aesAlg.CreateDecryptor(key, iv);
        return decryptor.TransformFinalBlock(input);
    }

    private struct HeaderRaw
    {
        public readonly FixedSpan Nonce;
        public readonly FixedSpan Payload;
        public readonly FixedSpan Mac;

        public HeaderRaw(FixedSpan buffer, int offset, int length)
        {
            Nonce = buffer.Slice(offset, 16);
            Payload = buffer.Slice(offset + Nonce.Length, length - 48);
            Mac = buffer.Slice(offset + Nonce.Length + Payload.Length, 32);
        }
    }

    private class Header
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