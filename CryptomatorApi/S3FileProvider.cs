using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using CryptomatorApi.Core;

namespace CryptomatorApi;

public class S3FileProvider : IFileProvider
{
    private readonly IAmazonS3 _api;
    private readonly string _bucketName;

    public S3FileProvider(IAmazonS3 api, string bucketName)
    {
        _api = api;
        _bucketName = bucketName;
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

    public async Task<string> ReadAllTextAsync(string filePath, CancellationToken cancellationToken)
    {
        filePath = AddRoot(filePath);
        var response = await _api.GetObjectAsync(new GetObjectRequest
        {
            BucketName = _bucketName,
            Key = filePath
        }, cancellationToken).ConfigureAwait(false);
        await using var s = response.ResponseStream;
        using var sr = new StreamReader(s);
        return await sr.ReadToEndAsync().ConfigureAwait(false);
    }

    public async Task<string[]> ReadAllLinesAsync(string filePath, CancellationToken cancellationToken)
    {
        var tmp = await ReadAllTextAsync(filePath, cancellationToken).ConfigureAwait(false);
        return tmp.Split(Environment.NewLine);
    }

    public async Task<bool> HasFilesAsync(string folderPath, CancellationToken cancellationToken)
    {
        folderPath = AddRoot(folderPath);
        var request = new ListObjectsV2Request
        {
            BucketName = _bucketName,
            Prefix = folderPath,
            MaxKeys = 1
        };
        var response = await _api.ListObjectsV2Async(request, cancellationToken).ConfigureAwait(false);
        return response.S3Objects.Any();
    }

    public async IAsyncEnumerable<string> GetDirectoriesAsync(string folderPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var info in GetFileSystemInfosAsync(folderPath, cancellationToken).ConfigureAwait(false))
        {
            var isDirectory = (info.Attributes & FileAttributes.Directory) != 0;
            if (isDirectory)
                yield return info.FullName;
        }
    }

    public async IAsyncEnumerable<DirOfFileInfo> GetFileSystemInfosAsync(string folderPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        folderPath = AddRoot(folderPath);
        // Build your request to list objects in the bucket
        var request = new ListObjectsV2Request
        {
            BucketName = _bucketName,
            Prefix = folderPath
        };

        var result = new Dictionary<string, DirOfFileInfo>();
        do
        {
            var response = await _api.ListObjectsV2Async(request, cancellationToken).ConfigureAwait(false);

            foreach (var responseS3Object in response.S3Objects)
            {
                string localPath;
                var isFolder = IsFolder(responseS3Object);
                var index = responseS3Object.Key.IndexOf('/', folderPath.Length + 1);
                if (index != -1)
                {
                    localPath = responseS3Object.Key.Substring(0, index);
                    isFolder = true;
                }
                else
                {
                    localPath = responseS3Object.Key;
                }

                if (!result.ContainsKey(localPath))
                {
                    var info = new DirOfFileInfo(
                        Path.GetFileName(localPath),
                        RemoveRoot(localPath),
                        isFolder ? FileAttributes.Directory : default);
                    result.Add(localPath, info);
                }
            }

            if (response.IsTruncated)
                request.ContinuationToken = response.ContinuationToken;
            else
                request = null;
        } while (request != null);

        foreach (var resultValue in result.Values) yield return resultValue;
    }

    public async IAsyncEnumerable<string> GetFilesAsync(string folderPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var info in GetFileSystemInfosAsync(folderPath, cancellationToken).ConfigureAwait(false))
        {
            var isDirectory = (info.Attributes & FileAttributes.Directory) != 0;
            if (!isDirectory)
                yield return info.FullName;
        }
    }

    public async Task<Stream> OpenReadAsync(string filePath, CancellationToken cancellationToken)
    {
        filePath = AddRoot(filePath);
        var response = await _api.GetObjectStreamAsync(_bucketName, filePath, null, cancellationToken)
            .ConfigureAwait(false);
        return response;
    }

    private string AddRoot(string path)
    {
        return path.Trim('/');
    }

    private string RemoveRoot(string path)
    {
        return path.TrimStart('/');
    }

    private bool IsFolder(S3Object x)
    {
        return x.Key.EndsWith(@"/") && x.Size == 0;
    }
}