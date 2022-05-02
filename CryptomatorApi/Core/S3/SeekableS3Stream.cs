using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;

namespace CryptomatorApi.Core.S3
{
    internal sealed class SeekableS3Stream : AsyncStream
    {
        private readonly IAmazonS3 _s3Client;
        private readonly bool _leaveOpen;
        private readonly string _bucketName;
        private readonly string _keyName;

        private GetObjectResponse _latestGetObjectResponse;
        private long _fullFileSize;
        private long _position = 0;

        public override bool CanRead => _latestGetObjectResponse?.ResponseStream?.CanRead == true;

        public override bool CanSeek => true;

        public override bool CanWrite => false;

        public override long Length => _fullFileSize;

        public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }

        public long SeekCount { get; private set; }

        public static Task<Stream> OpenFileAsync(IAmazonS3 s3Client, string bucketName, string keyName, bool leaveClientOpen)
        {
            var seekableStream = new SeekableS3Stream(s3Client, bucketName, keyName, leaveClientOpen);
            try
            {
                return seekableStream.OpenFileStreamAsync();
            }
            catch (Exception)
            {
                seekableStream.Dispose();
                throw;
            }
        }

        private SeekableS3Stream(IAmazonS3 s3Client, string bucketName, string keyName, bool leaveOpen)
        {
            _s3Client = s3Client;
            _leaveOpen = leaveOpen;
            _bucketName = bucketName;
            _keyName = keyName;
        }

        private async Task<Stream> OpenFileStreamAsync()
        {
            GetObjectRequest request = new GetObjectRequest
            {
                BucketName = _bucketName,
                Key = _keyName
            };
            _latestGetObjectResponse = await _s3Client.GetObjectAsync(request);
            _fullFileSize = _latestGetObjectResponse.ContentLength;
            return this;
        }

        public override void Flush()
        {
            _latestGetObjectResponse.ResponseStream.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return _latestGetObjectResponse.ResponseStream.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            _position += count;
            return _latestGetObjectResponse.ResponseStream.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            _position += count;
            return _latestGetObjectResponse.ResponseStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        public override async Task<long> SeekAsync(long offset, SeekOrigin origin, CancellationToken cancellationToken)
        {
            SeekCount++;

            long newStreamPos;
            switch (origin)
            {
                case SeekOrigin.Begin:
                    newStreamPos = offset;
                    break;
                case SeekOrigin.End:
                    newStreamPos = Length + offset;
                    break;
                case SeekOrigin.Current:
                    newStreamPos = _position + offset;
                    break;
                default:
                    throw new ArgumentException(nameof(origin));
            }

            if (newStreamPos == _position)
                return _position;

            _latestGetObjectResponse?.Dispose();

            var request = new GetObjectRequest
            {
                BucketName = _bucketName,
                Key = _keyName,
                ByteRange = new ByteRange(newStreamPos, Length)
            };

            _latestGetObjectResponse = await _s3Client.GetObjectAsync(request, cancellationToken).ConfigureAwait(false);

            _position = newStreamPos;
            return newStreamPos;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try
                {
                    if (_latestGetObjectResponse != null)
                        _latestGetObjectResponse.Dispose();
                }
                catch (Exception) { }

                try
                {
                    if (!_leaveOpen && _s3Client != null)
                        _s3Client.Dispose();
                }
                catch (Exception) { }
            }

            base.Dispose(disposing);
        }
    }
}
