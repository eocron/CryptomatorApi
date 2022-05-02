using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using CryptomatorApi.Core.S3;

namespace CryptomatorApi.Providers;

public class S3FileProvider : IFileProvider
{
    private readonly IAmazonS3 _api;
    private readonly string _bucketName;
    private readonly bool _requestMetadata;
    private readonly char _separator = '/';

    public S3FileProvider(IAmazonS3 api, string bucketName, bool requestMetadata = false)
    {
        _api = api;
        _bucketName = bucketName;
        _requestMetadata = requestMetadata;
    }

    public async Task<bool> IsFileExistsAsync(string filePath, CancellationToken cancellationToken)
    {
        filePath = AddRoot(filePath);
        try
        {
            await _api.GetObjectMetadataAsync(new GetObjectMetadataRequest
            {
                BucketName = _bucketName,
                Key = filePath
            }, cancellationToken).ConfigureAwait(false);

            return true;
        }

        catch (AmazonS3Exception ex)
        {
            if (ex.StatusCode == HttpStatusCode.NotFound)
                return false;
            throw;
        }
    }

    public async IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfosAsync(string folderPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        folderPath = AddRoot(folderPath);
        var request = new ListObjectsV2Request
        {
            BucketName = _bucketName,
            Prefix = folderPath
        };

        var result = new Dictionary<(string, bool), CryptomatorFileSystemInfo>();
        while(true)
        {
            var response = await _api.ListObjectsV2Async(request, cancellationToken).ConfigureAwait(false);

            foreach (var responseS3Object in response.S3Objects)
            {
                string localPath;
                var isFolder = IsFolder(responseS3Object);
                var index = responseS3Object.Key.IndexOf(_separator, folderPath.Length + 1);
                if (index != -1)
                {
                    localPath = responseS3Object.Key.Substring(0, index);
                    isFolder = true;
                }
                else
                {
                    localPath = responseS3Object.Key;
                }

                if (!result.ContainsKey((localPath, isFolder)))
                {
                    CryptomatorFileSystemInfo tmp;
                    if (isFolder)
                    {
                        tmp = new CryptomatorDirectoryInfo();
                    }
                    else
                    {
                        tmp = new CryptomatorFileInfo();
                    }

                    tmp.Name = Path.GetFileName(localPath);
                    tmp.FullName = RemoveRoot(localPath);
                    tmp.MetaData = new Dictionary<string, string>
                    {
                        { nameof(responseS3Object.ETag), responseS3Object.ETag },
                        { nameof(responseS3Object.StorageClass), responseS3Object.StorageClass.Value }
                    };

                    if (_requestMetadata)
                    {
                        var responseMeta = await _api.GetObjectMetadataAsync(new GetObjectMetadataRequest
                            {
                                BucketName = _bucketName,
                                Key = responseS3Object.Key
                            }, cancellationToken)
                            .ConfigureAwait(false);
                        foreach (var mkey in responseMeta.Metadata.Keys)
                        {
                            tmp.MetaData[mkey] = responseMeta.Metadata[mkey];
                        }
                    }
                    result.Add((localPath,isFolder), tmp);
                }
            }

            if (response.IsTruncated)
                request.ContinuationToken = response.ContinuationToken;
            else
                break;
        }

        foreach (var resultValue in result.Values) yield return resultValue;
    }

    public async Task<Stream> OpenReadAsync(string filePath, CancellationToken cancellationToken)
    {
        filePath = AddRoot(filePath);
        var response = await SeekableS3Stream.OpenFileAsync(_api, _bucketName, filePath);
        return response;
    }

    private string AddRoot(string path)
    {
        return path.Trim(_separator);
    }

    private string RemoveRoot(string path)
    {
        return path.TrimStart(_separator);
    }

    private bool IsFolder(S3Object x)
    {
        return x.Key.EndsWith(_separator) && x.Size == 0;
    }
}