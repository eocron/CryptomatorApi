using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

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

        public static Task<int> ReadAsync(this Stream stream, FixedSpan buffer, CancellationToken cancellationToken)
        {
            return stream.ReadAsync(buffer.Data, buffer.Offset, buffer.Length, cancellationToken);
        }

        public static Task<int> ReadAsync(this Stream stream, FixedSpan buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return stream.ReadAsync(buffer.Data, buffer.Offset + offset, Math.Min(buffer.Length, count), cancellationToken);
        }
    }
}
