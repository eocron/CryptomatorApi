using CryptomatorApi;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;

namespace Cryptomator.WebApi.Controllers
{
    [ApiController]
    public class FileController : ControllerBase
    {

        private readonly ILogger<FileController> _logger;
        private readonly ICryptomatorApi _api;
        private readonly IContentTypeProvider _contentTypeProvider;

        public FileController(ILogger<FileController> logger, ICryptomatorApi api, IContentTypeProvider contentTypeProvider)
        {
            _logger = logger;
            _api = api;
            _contentTypeProvider = contentTypeProvider;
        }

        [HttpGet("/api/files/search")]
        public async Task<IActionResult> GetFiles(
            [FromQuery(Name = "p")]string folderPath, 
            [FromQuery(Name = "sp")]string searchPattern, 
            [FromQuery(Name = "so")]SearchOption searchOption,
            CancellationToken cancellationToken)
        {
            try
            {
                var result = new List<string>();
                await foreach (var file in _api.GetFiles(folderPath, searchPattern, searchOption, cancellationToken).ConfigureAwait(false))
                {
                    result.Add(file.FullName);
                }

                return Ok(result);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to serve folder: {0}", folderPath);
                return BadRequest();
            }
        }

        [HttpGet("/api/dirs/search")]
        public async Task<IActionResult> GetDirectories(
            [FromQuery(Name = "p")] string folderPath,
            [FromQuery(Name = "sp")] string searchPattern,
            [FromQuery(Name = "so")] SearchOption searchOption,
            CancellationToken cancellationToken)
        {
            try
            {
                var result = new List<CryptomatorDirectoryInfo>();
                await foreach (var folder in _api.GetDirectories(folderPath, searchPattern, searchOption, cancellationToken).ConfigureAwait(false))
                {
                    result.Add(folder);
                }

                return Ok(result);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to serve folder: {0}", folderPath);
                return BadRequest();
            }
        }

        [HttpGet("/api/files/{filePath}")]
        public async Task<IActionResult> GetFile(string filePath, CancellationToken cancellationToken)
        {
            filePath = Uri.UnescapeDataString(filePath);
            try
            {
                if (!_contentTypeProvider.TryGetContentType(filePath, out var contentType))
                    contentType = "application/octet-stream";

                var fileStream = await _api.OpenReadAsync(filePath, cancellationToken).ConfigureAwait(false);
                return File(fileStream, contentType, Path.GetFileName(filePath));
            }
            catch (FileNotFoundException fnfex)
            {
                _logger.LogWarning(fnfex, "File not found: {0}", filePath);
                return NotFound();
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to serve file: {0}", filePath);
                return BadRequest();
            }
        }
    }
}