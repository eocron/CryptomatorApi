using System;

namespace CryptomatorApi.Core
{
    /// <summary>
    /// Robust version of Span, which allows internal access to data
    /// </summary>
    internal readonly struct FixedSpan
    {
        public readonly byte[] Data;
        public readonly int Length;
        public readonly int Offset;

        public FixedSpan(byte[] data, int offset, int length)
        {
            Data = data;
            Offset = offset;
            Length = length;
        }

        public FixedSpan(byte[] data)
        {
            Data = data;
            Offset = 0;
            Length = data.Length;
        }

        public FixedSpan Slice(int offset, int length)
        {
            return new FixedSpan(Data, Offset + offset, length);
        }

        public byte[] ToArray()
        {
            var bytes = new byte[Length];
            Array.Copy(Data, Offset, bytes, 0, Length);
            return bytes;
        }

        public byte this[int i] => Data[i + Offset];
    }
}
