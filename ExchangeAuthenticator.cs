using Microsoft.Exchange.WebServices.Data;
using Penguin.Authentication.Abstractions;
using Penguin.Authentication.Abstractions.Interfaces;
using System;
using System.Threading.Tasks;

namespace Penguin.Authentication.Exchange
{
    public class ExchangeAuthenticator : IAuthenticator
    {
        public static Uri Endpoint { get; private set; }

        public ExchangeAuthenticator()
        {
        }

        public ExchangeAuthenticator(Uri endpoint)
        {
            Endpoint = endpoint;
        }

        private static bool RedirectionCallback(string url)
        {
            // Return true if the URL is an HTTPS URL.
            return url.ToLower(System.Globalization.CultureInfo.CurrentCulture).StartsWith("https://");
        }

        public async Task<AuthenticationResult> Authenticate(string Username, string Password)
        {
            ExchangeService service = new()
            {
                Credentials = new WebCredentials(Username, Password),
                TraceEnabled = true
            };

            try
            {
                if (Endpoint is null)
                {
                    service.AutodiscoverUrl(Username, RedirectionCallback);
                    Endpoint = service.Url;
                }
                else
                {
                    service.Url = Endpoint;
                }

                FindFoldersResults findFolderResults = await service.FindFolders(WellKnownFolderName.Root, new SearchFilter.IsGreaterThan(FolderSchema.TotalCount, 0), new FolderView(10)).ConfigureAwait(false);

                return new AuthenticationResult()
                {
                    IsValid = true
                };
            }
            catch (ServiceRequestException srex) when (srex.Message.Contains("(401)"))
            {
                return new AuthenticationResult()
                {
                    IsValid = false
                };
            }
            catch (Exception ex)
            {
                return new AuthenticationResult()
                {
                    Exception = ex,
                    IsValid = false
                };
            }
        }
    }
}