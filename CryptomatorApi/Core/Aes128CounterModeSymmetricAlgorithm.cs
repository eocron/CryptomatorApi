using System;
using System.Security.Cryptography;

namespace CryptomatorApi.Core;

internal sealed class Aes128CounterModeSymmetricAlgorithm : SymmetricAlgorithm
{
    private readonly AesManaged _aes;
    private readonly byte[] _counter;

    public Aes128CounterModeSymmetricAlgorithm(byte[] counter)
    {
        if (counter == null) throw new ArgumentNullException(nameof(counter));
        if (counter.Length != 16)
            throw new ArgumentException(string.Format(
                "Counter size must be same as block size (actual: {0}, expected: {1})",
                counter.Length, 16));

        _aes = new AesManaged
        {
            Mode = CipherMode.ECB,
            Padding = PaddingMode.None
        };

        _counter = counter;
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] ignoredParameter)
    {
        return new CounterModeCryptoTransform(_aes, rgbKey, _counter);
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] ignoredParameter)
    {
        return new CounterModeCryptoTransform(_aes, rgbKey, _counter);
    }

    public override void GenerateKey()
    {
        _aes.GenerateKey();
    }

    public override void GenerateIV()
    {
        // IV not needed in Counter Mode
    }
}