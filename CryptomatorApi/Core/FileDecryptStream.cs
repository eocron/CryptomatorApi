using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CryptomatorApi.Core.Contract;

namespace CryptomatorApi.Core
{
    public class FileDecryptStream : Stream
    {
        private readonly Stream _inner;
        private byte[] _buffer = new byte[32768 + 48];
        private int _blockNum = 0;
        private Header _header;
        private readonly Keys _keys;
        private byte[] _current;
        private int _currentPos;
        private long _pos;
        public FileDecryptStream(Stream inner, Keys keys)
        {
            _keys = keys;
            _inner = inner;
        }

        public override void Flush()
        {
            _inner.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_header == null)
            {
                _header = ReadHeader(_inner, _keys);
                _current = ReadBlock(_inner, _header, ref _blockNum);
                _currentPos = 0;
            }

            if (_current == null)
                return 0;

            for (var i = 0; i < count; i++)
            {
                if (_currentPos == _current.Length)
                {
                    _currentPos = 0;
                    _current = ReadBlock(_inner, _header, ref _blockNum);
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

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _pos;
            set => throw new NotSupportedException();
        }

        private byte[] ReadBlock(Stream stream, Header header, ref int blockNum)
        {
            //read file content payload
            var chunk = _buffer;
            var read = stream.Read(chunk, 0, chunk.Length);
            if (read == 0)
                return null;

            var chunkHeader = new HeaderRaw(chunk, 0, read);

            var beBlockNum = BitConverter.GetBytes((long)blockNum);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(beBlockNum);

            header.ChunkHmac.Initialize();
            header.ChunkHmac.Update(header.HeaderNonce);
            header.ChunkHmac.Update(beBlockNum);
            header.ChunkHmac.Update(chunkHeader.Nonce);
            header.ChunkHmac.DoFinal(chunkHeader.Payload);
            if (!Equals(header.ChunkHmac.Hash, chunkHeader.Mac))
                throw new IOException("Encrypted file fails integrity check.");

            var result = AesCtr(chunkHeader.Payload, header.ContentKey, chunkHeader.Nonce);
            blockNum++;
            return result;
        }

        public struct  HeaderRaw
        {
            public byte[] Nonce;
            public byte[] Payload;
            public byte[] Mac;
            public HeaderRaw(byte[] buffer, int offset, int length)
            {
                Nonce = Slice(buffer, offset, 16);
                Payload = Slice(buffer, offset + Nonce.Length, length - 48);
                Mac = Slice(buffer, offset + Nonce.Length + Payload.Length, 32);
            }
        }

        private static Header ReadHeader(Stream stream, Keys keys)
        {
            var all = new byte[16 + 40 + 32];
            if (stream.Read(all) != all.Length)
                throw new IOException("Invalid file header.");

            var chunkHeader = new HeaderRaw(all, 0, all.Length);

            var headerHmac = new Hmac(keys.MacKey);
            headerHmac.Update(chunkHeader.Nonce);
            headerHmac.DoFinal(chunkHeader.Payload);
            if (!Equals(headerHmac.Hash, chunkHeader.Mac))
                throw new IOException("Encrypted file fails integrity check.");

            var cleartextPayload = AesCtr(chunkHeader.Payload, keys.MasterKey, chunkHeader.Nonce);
            var contentKey = Slice(cleartextPayload, 8, 32);

            var chunkHmac = new Hmac(keys.MacKey);

            return new Header
            {
                ContentKey = contentKey,
                ChunkHmac = chunkHmac,
                HeaderNonce = chunkHeader.Nonce
            };
        }

        private static bool Equals(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            if (a1.Length != a2.Length)
            {
                return false;
            }

            for (var i = 0; i < a1.Length; i++)
            {
                if (a1[i] != a2[i])
                {
                    return false;
                }
            }

            return true;
        }

        private class Header
        {
            public byte[] ContentKey;
            public Hmac ChunkHmac;
            public byte[] HeaderNonce;
        }

        private static byte[] Slice(byte[] input, int offset, int length)
        {
            var output = new byte[length];
            Array.Copy(input, offset, output, 0, length);
            return output;
        }

        private static byte[] AesCtr(byte[] input, byte[] key, byte[] iv)
        {
            iv = (byte[])iv.Clone(); //use a copy to avoid updating original IV.

            //Since we're always decrypting an in-memory chunk we don't bother with streams
            using var aesAlg = new Aes128CounterModeSymmetricAlgorithm(iv);
            var decryptor = aesAlg.CreateDecryptor(key, iv);
            return decryptor.TransformFinalBlock(input, 0, input.Length);
        }

        private sealed class Hmac : HMACSHA256
        {
            public Hmac(byte[] key) : base(key)
            {
            }

            public void Update(byte[] input)
            {
                TransformBlock(input, 0, input.Length, null, 0);
            }

            public void DoFinal(byte[] input)
            {
                TransformFinalBlock(input, 0, input.Length);
            }
        }
    }
}
