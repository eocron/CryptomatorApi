using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptomatorApi.Core
{
    internal static class FixedSpanExtensions
    {
        public static int TransformBlock(
            this ICryptoTransform transform,
            FixedSpan inputBuffer)
        {
            return transform.TransformBlock(inputBuffer.Data, inputBuffer.Offset, inputBuffer.Length, null, 0);
        }

        public static byte[] TransformFinalBlock(this ICryptoTransform transform, FixedSpan inputBuffer)
        {
            return transform.TransformFinalBlock(inputBuffer.Data, inputBuffer.Offset, inputBuffer.Length);
        }

        public static int Read(this Stream stream, FixedSpan buffer)
        {
            return stream.Read(buffer.Data, buffer.Offset, buffer.Length);
        }

        public static int Read(this Stream stream, FixedSpan buffer, int offset, int count)
        {
            return stream.Read(buffer.Data, buffer.Offset + offset, Math.Min(buffer.Length, count));
        }
    }
}
