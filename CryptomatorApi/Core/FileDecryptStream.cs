using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using CryptomatorApi.Core.Contract;

namespace CryptomatorApi.Core
{
    public class FileDecryptStream : Stream
    {
        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
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

        public override bool CanRead { get; }
        public override bool CanSeek { get; }
        public override bool CanWrite { get; }
        public override long Length { get; }
        public override long Position { get; set; }


        public static void DecryptStream(Stream encryptedStream, Stream output, Keys keys)
        {
            using var reader = new BinaryReader(encryptedStream);
            using var writer = new BinaryWriter(output);
            //Read file header

            var headerNonce = reader.ReadBytes(16);
            var ciphertextPayload = reader.ReadBytes(40);
            var mac = reader.ReadBytes(32);

            var headerHmac = new Hmac(keys.MacKey);
            headerHmac.Update(headerNonce);
            headerHmac.DoFinal(ciphertextPayload);
            if (!headerHmac.Hash.SequenceEqual(mac))
                throw new IOException("Encrypted file fails integrity check.");

            var cleartextPayload = AesCtr(ciphertextPayload, keys.MasterKey, headerNonce);
            var contentKey = Slice(cleartextPayload, 8, 32);

            var chunkHmac = new Hmac(keys.MacKey);

            //Process all chunks
            for (var blocknum = 0; ; ++blocknum)
            {
                //read file content payload
                var chunk = reader.ReadBytes(32768 + 48);
                if (chunk.Length == 0)
                    break;

                var chunkNonce = Slice(chunk, 0, 16);
                var chunkpayload = Slice(chunk, chunkNonce.Length, chunk.Length - 48);
                var chunkmac = Slice(chunk, chunkNonce.Length + chunkpayload.Length, 32);


                var beBlockNum = BitConverter.GetBytes((long)blocknum);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(beBlockNum);

                chunkHmac.Initialize();
                chunkHmac.Update(headerNonce);
                chunkHmac.Update(beBlockNum);
                chunkHmac.Update(chunkNonce);
                chunkHmac.DoFinal(chunkpayload);
                if (!chunkHmac.Hash.SequenceEqual(chunkmac))
                    throw new IOException("Encrypted file fails integrity check.");

                var decryptedContent = AesCtr(chunkpayload, contentKey, chunkNonce);
                writer.Write(decryptedContent);
            }
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
                TransformBlock(input, 0, input.Length, input, 0);
            }

            public void DoFinal(byte[] input)
            {
                TransformFinalBlock(input, 0, input.Length);
            }
        }
    }
}
