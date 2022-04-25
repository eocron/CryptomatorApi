using System;
using System.Text;

// This class used for JWT strings, which don't contain padding.
namespace CryptomatorApi.Core;

internal static class Base64Url
{
    public static byte[] ToBytes(string input)
    {
        //Per RFC4648, replace + with - and / with _
        return Convert.FromBase64String(input.Replace('-', '+').Replace('_', '/'));
    }

    public static string Encode(byte[] input)
    {
        var output = Convert.ToBase64String(input);
        output = output.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return output;
    }

    public static byte[] Decode(string input)
    {
        var output = input;

        output = output.Replace('-', '+').Replace('_', '/');
        switch (output.Length % 4)
        {
            case 2:
                output += "==";
                break;
            case 3:
                output += "=";
                break;
        }

        var converted = Convert.FromBase64String(output); // Standard base64 decoder

        return converted;
    }

    public static string DecodeToString(string input)
    {
        return Encoding.UTF8.GetString(Decode(input));
    }
}