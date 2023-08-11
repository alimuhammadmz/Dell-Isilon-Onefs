using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Net.Http.Headers;
using System.Net;
using Aws4RequestSigner;
using Newtonsoft.Json;
using System;
using System.IO;

namespace Program
{
    public class AppSettings
    {
        public string AccessKey { get; set; }
        public string SecretKey { get; set; }
        public string ServiceName { get; set; }
        public string BaseUrl { get; set; }
        public string SessionUrl { get; set; }
        public string DocumentUrl { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string BucketName { get; set; }
        public string BucketDescription { get; set; }
        public string Version { get; set; }
        public string FilePath { get; set; }
        public string UploadAs { get; set; }
        public string DownloadAs { get; set; }
        public string AwsRegion { get; set; }
        public string Signature_EmptyBody { get; set; }
    }

    public class OneFSLogic
    {
        public static string AccessKey;
        public static string SecretKey;
        public static string ServiceName;

        public string BaseUrl;
        public string SessionUrl;
        public string DocumentUrl;

        private string Username;
        private string Password;
        private string BucketName;
        private string BucketDescription;
        private string Version;

        private string FilePath;
        private string UploadAs;
        private string DownloadAs;

        public string AwsRegion;

        public string Signature_EmptyBody;

        public OneFSLogic()
        {
            string configPath = "/* Adjust the path as needed */";

            string configJson = System.IO.File.ReadAllText(configPath);
            AppSettings settings = JsonConvert.DeserializeObject<AppSettings>(configJson);

            AccessKey = settings.AccessKey;
            SecretKey = settings.SecretKey;
            ServiceName = settings.ServiceName;
            BaseUrl = settings.BaseUrl;
            SessionUrl = settings.SessionUrl;
            DocumentUrl = settings.DocumentUrl;
            Username = settings.Username;
            Password = settings.Password;
            BucketName = settings.BucketName;
            BucketDescription = settings.BucketDescription;
            Version = settings.Version;
            FilePath = settings.FilePath;
            UploadAs = settings.UploadAs;
            DownloadAs = settings.DownloadAs;
            AwsRegion = settings.AwsRegion;
            Signature_EmptyBody = settings.Signature_EmptyBody;
        }

        static async Task Main(string[] args)
        {
            try
            {
                OneFSLogic fileSystem = new OneFSLogic();

                var result = await fileSystem.Execute(fileSystem.BucketName);
                if (result == false)
                {
                    Console.WriteLine("Operation unsuccessful!");
                }
                else
                {
                    Console.WriteLine("Operation successful!");
                }
            }catch(Exception ex) { 
                Console.Write(ex.ToString());
            }
        }

        private async Task<bool> Execute(string bucketName)
        {
            try
            {
                var sessionHeaders = await InitializeSessionAsync();
                if (await CreateBucket(sessionHeaders, bucketName))
                {
                    var isUploaded = await UploadDocumentAsync(bucketName, UploadAs, sessionHeaders);
                    if (isUploaded == false)
                    {
                        Console.WriteLine("Document did not upload successfully!");
                        return false;
                    }
                    Console.WriteLine("Document uploaded successfully.");
                    var result = await DownloadBase64();
                    return true;
                }
                Console.WriteLine("Bucket creation unsuccessful!");
                return false;
            }catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        private async Task<bool> CreateBucket(List<string>? sessionHeaders, string bucketName)
        {
            if (sessionHeaders == null || sessionHeaders.Count == 0)
                return false;

            var signer = new AWS4RequestSigner(AccessKey, SecretKey);
            var requestBody = new
            {
                create_path = true,
                description = BucketDescription,
                name = bucketName,
                owner = "root",
                path = $"/ifs/{bucketName}"
            };
            string requestBodyJson = JsonConvert.SerializeObject(requestBody);

            var content = new StringContent(requestBodyJson, Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri($"{BaseUrl}/platform/{Version}/protocols/s3/buckets"),
                Content = content
            };
            var bypassHandler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) => true
            };

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("Cookie", $"isisessid={sessionHeaders[0]}");
            request.Headers.Referrer = new Uri(BaseUrl);
            request.Headers.Add("X-CSRF-Token", sessionHeaders[1]);

            request = await signer.Sign(request, "execute-api", AwsRegion);
            var client = new HttpClient(bypassHandler);
            var response = await client.SendAsync(request);

            var responseStr = await response.Content.ReadAsStringAsync();
           /* Console.WriteLine(responseStr + "\n\n"); */       //log this response

            if (response.IsSuccessStatusCode || (response.StatusCode == System.Net.HttpStatusCode.Conflict) )
            {
                return true;
            }
            return false;
        }

        private async Task<dynamic> InitializeSessionAsync()
        {
            var bypassHandler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) => true
            };

            using (HttpClient client = new HttpClient(bypassHandler))
            {
                client.BaseAddress = new Uri(BaseUrl);
                client.DefaultRequestHeaders.Accept.Clear();

                var requestBody = new
                {
                    username = Username,
                    password = Password,
                    services = new[] { "platform", "namespace" }
                };

                var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(requestBody), Encoding.UTF8, "application/json");
                HttpResponseMessage response = await client.PostAsync(SessionUrl, content);

                if (response.IsSuccessStatusCode)
                {
                    string setCookieHeader = response.Headers.GetValues("Set-Cookie").FirstOrDefault();
                    string CsrfToken = response.Headers.GetValues("X-CSRF-Token").FirstOrDefault();
                    string SessionId = "";

                    if (!string.IsNullOrEmpty(setCookieHeader))
                    {
                        SessionId = setCookieHeader.Split("=")[1].Split(";")[0];
                        List<string> sessionId_Csrf = new();
                        sessionId_Csrf.Add(SessionId);
                        sessionId_Csrf.Add(CsrfToken);

                        return sessionId_Csrf;
                    }
                }
                else
                {
                    Console.WriteLine($"Failed to initialize session. Status code: {response.StatusCode}");
                }
                return null;
            }
        }

        static string ConvertDocumentToBase64(string filePath)
        {
            byte[] documentBytes = System.IO.File.ReadAllBytes(filePath);
            return Convert.ToBase64String(documentBytes);
        }

        private async Task<bool> UploadDocumentAsync(string bucketName, string documentName, List<string> sessionHeaders)
        {
            string documentBase64 = ConvertDocumentToBase64(FilePath);
            var signer = new AWS4RequestSigner(AccessKey, SecretKey);
            var requestBody = new
            {
                data = documentBase64,
            };
            string requestBodyJson = JsonConvert.SerializeObject(requestBody);

            var content = new StringContent(requestBodyJson, Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Put,
                RequestUri = new Uri($"{DocumentUrl}/{bucketName}/{documentName}"),
                Content = content
            };
            var bypassHandler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) => true
            };

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/plain"));
            request = await signer.Sign(request, "execute-api", AwsRegion);
            var client = new HttpClient(bypassHandler);
            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                return true;
            }
            else
            {
                Console.WriteLine($"Failed to upload document. Status code: {response.StatusCode}");
                return false;
            }
        }
       
        public List<string> GetAuthorization()
        {

            HttpRequestMessage msg = new HttpRequestMessage(HttpMethod.Get, BaseUrl);
            msg.Headers.Host = msg.RequestUri.Host;


            DateTimeOffset utcNowSaved = DateTimeOffset.UtcNow;
            string amzLongDate = utcNowSaved.ToString("yyyyMMddTHHmmssZ");
            string amzShortDate = utcNowSaved.ToString("yyyyMMdd");

            List<string> authValues = new();

            authValues.Add(amzLongDate);
            authValues.Add(amzShortDate);
            
            var canonicalRequest = new StringBuilder();
            canonicalRequest.Append(msg.Method + "\n");
            canonicalRequest.Append(string.Join("/", msg.RequestUri.AbsolutePath.Split('/').Select(Uri.EscapeDataString)) + "\n");

            canonicalRequest.Append(GetCanonicalQueryParams(msg) + "\n"); // Query params to do.

            var headersToBeSigned = new List<string>();
            foreach (var header in msg.Headers.OrderBy(a => a.Key.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase))
            {
                canonicalRequest.Append(header.Key.ToLowerInvariant());
                canonicalRequest.Append(":");
                canonicalRequest.Append(string.Join(",", header.Value.Select(s => s.Trim())));
                canonicalRequest.Append("\n");
                headersToBeSigned.Add(header.Key.ToLowerInvariant());
            }
            canonicalRequest.Append("\n");

            var signedHeaders = string.Join(";", headersToBeSigned);
            canonicalRequest.Append(signedHeaders + "\n");
            canonicalRequest.Append(Signature_EmptyBody);        
            string stringToSign = "AWS4-HMAC-SHA256" + "\n" + amzLongDate + "\n" + amzShortDate + "/" + AwsRegion + "/" + ServiceName + "/aws4_request" + "\n" + Hash(Encoding.UTF8.GetBytes(canonicalRequest.ToString()));

            var dateKey = HmacSha256(Encoding.UTF8.GetBytes("AWS4" + Password), amzShortDate);
            var dateRegionKey = HmacSha256(dateKey, AwsRegion);
            var dateRegionServiceKey = HmacSha256(dateRegionKey, ServiceName);
            var signingKey = HmacSha256(dateRegionServiceKey, "aws4_request");

            var signature = ToHexString(HmacSha256(signingKey, stringToSign.ToString()));

            var credentialScope = amzShortDate + "/" + AwsRegion + "/" + ServiceName + "/aws4_request";
            var authorization = "AWS4-HMAC-SHA256 Credential=" + AccessKey + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;

            authValues.Add(authorization);

            Console.WriteLine("X-Amz-Date: " + authValues[0]);
            Console.WriteLine("\nAuthorization: " + authValues[2] + "\n");

            return authValues;
        }

        private static string GetCanonicalQueryParams(HttpRequestMessage request)
        {
            var values = new SortedDictionary<string, string>();

            var querystring = HttpUtility.ParseQueryString(request.RequestUri.Query);
            foreach (var key in querystring.AllKeys)
            {
                if (key == null)
                {
                    values.Add(Uri.EscapeDataString(querystring[key]), $"{Uri.EscapeDataString(querystring[key])}=");
                }
                else
                {
                    values.Add(Uri.EscapeDataString(key), $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(querystring[key])}");
                }
            }
            var queryParams = values.Select(a => a.Value);
            return string.Join("&", queryParams);
        }

        public static string Hash(byte[] bytesToHash)
        {
            return ToHexString(SHA256.Create().ComputeHash(bytesToHash));
        }
        
        private static string ToHexString(IReadOnlyCollection<byte> array)
        {
            var hex = new StringBuilder(array.Count * 2);
            foreach (var b in array)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        private static byte[] HmacSha256(byte[] key, string data)
        {
            return new HMACSHA256(key).ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        public async Task<string> DownloadBase64()
        {
            string documentBase64 = ConvertDocumentToBase64(FilePath);
            var signer = new AWS4RequestSigner(AccessKey, SecretKey);

            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri($"{DocumentUrl}/{BucketName}/{DownloadAs}")
            };
            var bypassHandler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) => true
            };

            request = await signer.Sign(request, "execute-api", AwsRegion);
            var client = new HttpClient(bypassHandler);
            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                string data = await response.Content.ReadAsStringAsync();
                return await response.Content.ReadAsStringAsync();
            }
            else
            {
                Console.WriteLine($"Failed to upload document. Status code: {response.StatusCode}");
                return "Failed!";
            }
        }
    }
}