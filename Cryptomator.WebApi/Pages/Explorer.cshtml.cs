using CryptomatorApi;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.StaticFiles;

namespace Cryptomator.WebApi.Pages
{
    public class ExplorerItemInfo
    {
        public string Name { get; set; }

        public string Link { get; set; }
    }
    public class ExplorerModel : PageModel
    {
        private readonly ILogger<ExplorerModel> _logger;
        private readonly IContentTypeProvider _contentTypeProvider;
        private readonly ICryptomatorApi _api;

        public ExplorerModel(ILogger<ExplorerModel> logger, IContentTypeProvider contentTypeProvider, ICryptomatorApi api)
        {
            _logger = logger;
            _contentTypeProvider = contentTypeProvider;
            _api = api;
        }



        [BindProperty(Name = "p", SupportsGet = true)]
        public string FilePath { get; set; }

        [BindProperty(Name = "r", SupportsGet = true)]
        public string CurrentDirectoryEscaped { get; set; }

        public List<ExplorerItemInfo> Directories { get; set; }

        public List<ExplorerItemInfo> Files { get; set; }
        public string Type { get; set; }


        /// <summary>
        /// https://stackoverflow.com/questions/14946421/why-do-webkit-browsers-need-to-download-the-entire-html5-video-mp4-before-play
        /// </summary>
        public string VideoLink { get; set; }

        public string ImageLink { get; set; }

        public async Task OnGet(CancellationToken cancellationToken)
        {
            if (!string.IsNullOrWhiteSpace(FilePath))
            {
                if (!_contentTypeProvider.TryGetContentType(FilePath, out var contentType))
                    contentType = "application/octet-stream";
                Type = contentType;
                if (contentType.Contains("video"))
                {
                    VideoLink = "/api/files/" + Uri.EscapeDataString(FilePath);
                }
                else if(contentType.Contains("image"))
                {
                    ImageLink = "/api/files/" + Uri.EscapeDataString(FilePath);
                }
            }

            Directories = new List<ExplorerItemInfo>();
            Files = new List<ExplorerItemInfo>();
            var currentDir = SafeUnescape(CurrentDirectoryEscaped);
            var parent = MapDirectory(SafeGetDirectoryName(currentDir));
            parent.Name = "..";
            Directories.Add(parent);

            await foreach (var fsi in _api.GetFileSystemInfos(currentDir, cancellationToken).ConfigureAwait(false))
            {
                if (fsi is CryptomatorDirectoryInfo)
                {
                    Directories.Add(MapDirectory(fsi.FullName));
                }
                else if(fsi is CryptomatorFileInfo)
                {
                    Files.Add(MapFile(fsi.FullName));
                }
            }
        }

        private string SafeGetDirectoryName(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;
            return Path.GetDirectoryName(path);
        }

        private string SafeEscape(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;
            return Uri.EscapeDataString(path);
        }

        private string SafeUnescape(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;
            return Uri.UnescapeDataString(path);
        }

        private ExplorerItemInfo MapDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return new ExplorerItemInfo()
                {
                    Name = "***empty***",
                    Link = $"/explorer"
                };
            return new ExplorerItemInfo
            {
                Name = Path.GetFileName(path),
                Link = $"/explorer?r={SafeEscape(path)}"
            };
        }

        private ExplorerItemInfo MapFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;
            return new ExplorerItemInfo
            {
                Name = Path.GetFileName(path),
                Link = $"/explorer?r={CurrentDirectoryEscaped}&p={SafeEscape(path)}"
            };
        }
    }
}