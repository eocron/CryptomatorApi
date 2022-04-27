﻿using System;
using System.IO;
using System.Security.Cryptography;
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
        if (_header == null)
        {
            _header = ReadHeader();
            _current = ReadBlock();
            _currentPos = 0;
        }

        if (_current == null)
            return 0;

        for (var i = 0; i < count; i++)
        {
            if (_currentPos == _current.Length)
            {
                _currentPos = 0;
                _current = ReadBlock();
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

    private byte[] ReadBlock()
    {
        var chunk = _buffer;
        int tmpRead;
        TryReadExactly(_inner, chunk, 0, chunk.Length, out tmpRead);
        if (tmpRead == 0)
            return null;

        var chunkHeader = new HeaderRaw(chunk, 0, tmpRead);

        var beBlockNum = BitConverter.GetBytes((long)_blockNum);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(beBlockNum);

        _header.ChunkHmac.Initialize();
        _header.ChunkHmac.Update(_header.HeaderNonce);
        _header.ChunkHmac.Update(beBlockNum);
        _header.ChunkHmac.Update(chunkHeader.Nonce);
        _header.ChunkHmac.DoFinal(chunkHeader.Payload);
        if (!Equals(_header.ChunkHmac.Hash, chunkHeader.Mac))
            throw new IOException("Encrypted file fails integrity check.");

        var result = AesCtr(chunkHeader.Payload, _header.ContentKey, chunkHeader.Nonce);
        _blockNum++;
        return result;
    }

    /// <summary>
    /// Due to how some streams works we need to read exact blocks.
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="buffer"></param>
    /// <param name="offset"></param>
    /// <param name="count"></param>
    /// <param name="totalRead"></param>
    /// <returns></returns>
    private static bool TryReadExactly(Stream stream, byte[] buffer, int offset, int count, out int totalRead)
    {
        totalRead = 0;
        int read;
        while (count > 0 && (read = stream.Read(buffer, offset, count)) > 0)
        {
            count -= read;
            offset += read;
            totalRead += read;
        }

        return count == 0;
    }

    private Header ReadHeader()
    {
        const int headerSize = 16 + 40 + 32;
        var chunk = _buffer;
        if (_inner.Read(chunk, 0, headerSize) != headerSize)
            throw new IOException("Invalid file header.");

        var chunkHeader = new HeaderRaw(chunk, 0, headerSize);

        var headerHmac = new Hmac(_keys.MacKey);
        headerHmac.Update(chunkHeader.Nonce);
        headerHmac.DoFinal(chunkHeader.Payload);
        if (!Equals(headerHmac.Hash, chunkHeader.Mac))
            throw new IOException("Encrypted file fails integrity check.");

        var cleartextPayload = AesCtr(chunkHeader.Payload, _keys.MasterKey, chunkHeader.Nonce);
        var contentKey = Slice(cleartextPayload, 8, 32);

        return new Header(contentKey, new Hmac(_keys.MacKey), chunkHeader.Nonce);
    }

    private static bool Equals(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
    {
        if (a1.Length != a2.Length) return false;

        for (var i = 0; i < a1.Length; i++)
            if (a1[i] != a2[i])
                return false;

        return true;
    }

    private static ReadOnlySpan<byte> Slice(byte[] input, int offset, int length)
    {
        return input.AsSpan(offset, length);
    }

    private static byte[] AesCtr(ReadOnlySpan<byte> input, byte[] key, ReadOnlySpan<byte> ivSpan)
    {
        var iv = ivSpan.ToArray(); //use a copy to avoid updating original IV.

        //Since we're always decrypting an in-memory chunk we don't bother with streams
        using var aesAlg = new Aes128CounterModeSymmetricAlgorithm(iv);
        var decryptor = aesAlg.CreateDecryptor(key, iv);
        return decryptor.TransformFinalBlock(input.ToArray(), 0, input.Length);
    }

    private ref struct HeaderRaw
    {
        public readonly ReadOnlySpan<byte> Nonce;
        public readonly ReadOnlySpan<byte> Payload;
        public readonly ReadOnlySpan<byte> Mac;

        public HeaderRaw(byte[] buffer, int offset, int length)
        {
            Nonce = Slice(buffer, offset, 16);
            Payload = Slice(buffer, offset + Nonce.Length, length - 48);
            Mac = Slice(buffer, offset + Nonce.Length + Payload.Length, 32);
        }
    }

    private class Header
    {
        public readonly Hmac ChunkHmac;
        public readonly byte[] ContentKey;
        public readonly byte[] HeaderNonce;

        public Header(ReadOnlySpan<byte> contentKey, Hmac chunkHmac, ReadOnlySpan<byte> headerNonce)
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

        public void Update(ReadOnlySpan<byte> input)
        {
            TransformBlock(input.ToArray(), 0, input.Length, null, 0);
        }

        public void DoFinal(ReadOnlySpan<byte> input)
        {
            TransformFinalBlock(input.ToArray(), 0, input.Length);
        }
    }
}