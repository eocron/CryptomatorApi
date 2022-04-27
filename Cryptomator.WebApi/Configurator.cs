using Amazon.Runtime;
using Amazon.S3;
using CryptomatorApi;
using CryptomatorApi.Core;
using Microsoft.AspNetCore.StaticFiles;

namespace Cryptomator.WebApi
{
    public class Configurator
    {
        public static void Configure(IServiceCollection services)
        {
            services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();
            services.AddSingleton(x => x.GetRequiredService<IConfiguration>().Get<CryptomatorSettings>());
            services.AddSingleton<IAmazonS3>(x =>
            {
                var cfg = x.GetRequiredService<CryptomatorSettings>().S3;
                var amazonConfig = new AmazonS3Config();
                amazonConfig.UseHttp = true;
                amazonConfig.ServiceURL = cfg.Endpoint;
                var credentials = new BasicAWSCredentials(cfg.AccessKey, cfg.SecretKey);
                return new AmazonS3Client(credentials, amazonConfig);
            });
            services.AddSingleton<IFileProvider>(x =>
            {
                var cfg = x.GetRequiredService<CryptomatorSettings>();
                if (cfg.S3 == null)
                    return new SimpleFileProvider();
                return new S3FileProvider(x.GetRequiredService<IAmazonS3>(), cfg.S3.BucketName);
            });
            services.AddSingleton<IPathHelper>(x =>
            {
                var cfg = x.GetRequiredService<CryptomatorSettings>();
                if (cfg.S3 == null)
                    return new PathHelper(Path.DirectorySeparatorChar);
                return new PathHelper('/');
            });
            services.AddSingleton<ICryptomatorApiFactory, CryptomatorApiFactory>();
            services.AddSingleton(x =>
            {
                var cfg = x.GetRequiredService<CryptomatorSettings>();
                return x.GetRequiredService<ICryptomatorApiFactory>().Create(cfg.Password, cfg.VaultPath);
            });
            services.AddSingleton<IContentTypeProvider>(x => new FileExtensionContentTypeProvider());
        }
    }
}
