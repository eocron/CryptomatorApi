using System.Security.Cryptography;

namespace CryptomatorApi.Misreant;

internal static class Utils
{
    public static void Multiply(byte[] input)
    {
        var carry = input[0] >> 7;

        for (var i = 0; i < Constants.BlockSize - 1; ++i) input[i] = (byte)((input[i] << 1) | (input[i + 1] >> 7));

        var last = input[Constants.BlockSize - 1];
        input[Constants.BlockSize - 1] = (byte)((last << 1) ^ Subtle.ConstantTimeSelect(carry, Constants.R, 0));
    }

    public static void Xor(byte[] source, byte[] destination, int length)
    {
        Xor(source, 0, destination, 0, length);
    }

    public static void Xor(byte[] source, int sourceIndex, byte[] destination, int destinationIndex, int length)
    {
        for (var i = 0; i < length; ++i) destination[destinationIndex + i] ^= source[sourceIndex + i];
    }

    public static void Pad(byte[] buffer, int position)
    {
        buffer[position] = 0x80;

        for (var i = position + 1; i < Constants.BlockSize; ++i) buffer[i] = 0;
    }

    public static int Ceil(int dividend, int divisor)
    {
        return (dividend + divisor - 1) / divisor;
    }

    public static Aes CreateAes(CipherMode mode)
    {
        var aes = Aes.Create();

        aes.Mode = mode;
        aes.Padding = PaddingMode.None;

        return aes;
    }
}