namespace AuthMan.Api.Services;

public sealed class BirdEmailOptions
{
    public const string SectionName = "Bird";

    public string ApiKey { get; set; } = string.Empty;
    public string FromEmail { get; set; } = string.Empty;
    public string FromName { get; set; } = "Bird";
    public string BaseUrl { get; set; } = "https://us1.platform.bird.com";
    public string PublicApiBaseUrl { get; set; } = string.Empty;
}
