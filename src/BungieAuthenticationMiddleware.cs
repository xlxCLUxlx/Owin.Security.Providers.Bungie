/*
 * MIT License
 *
 * Copyright(c) 2018 Eric Boulden (xlxCLUxlx on GitHub)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.Globalization;
using System.Net.Http;

using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

using Owin.Security.Providers.Bungie.Properties;

namespace Owin.Security.Providers.Bungie
{
    /// <summary>
    /// The middleware registered with the owin application that acts as a factory only has one instance.
    /// </summary>
    public class BungieAuthenticationMiddleware : AuthenticationMiddleware<BungieAuthenticationOptions>
    {
        #region Fields

        /// <summary>
        /// Used for sending HTTP request and receiving HTTP resposnses from a resource URI.
        /// </summary>
        private readonly HttpClient _httpClient;

        /// <summary>
        /// Generic interface for OWIN logging.
        /// </summary>
        private readonly ILogger _logger;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="BungieAuthenticationMiddleware"/> class.
        /// </summary>
        /// <param name="next">The next middleware on the standard middleware pattern.</param>
        /// <param name="app">Tells Owin what middleware to use in the HTTP pipeline.</param>
        /// <param name="options">An instance of the <see cref="BungieAuthenticationOptions"/> class that contains 
        /// options used by the authentication middleware.</param>
        /// <remarks>
        /// This is a factory that creates instances of the handler that does the actual work of processing requests. 
        /// Only one instance of the middleware is instantiated. This checks the configuration in the options class 
        /// and if certain properties are null.
        /// </remarks>
        public BungieAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            BungieAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientId"));
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientSecret"));
            if (string.IsNullOrWhiteSpace(Options.ApiKey))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ApiKey"));

            _logger = app.CreateLogger<BungieAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new BungieAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof(BungieAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        #endregion

        #region Protected Methods

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.Bungie.BungieAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<BungieAuthenticationOptions> CreateHandler()
        {
            return new BungieAuthenticationHandler(_httpClient, _logger);
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Allows for custom validation by the client of the server certificate if set in the options.
        /// </summary>
        /// <param name="options">An instance of the <see cref="BungieAuthenticationOptions"/> class that contains 
        /// options used by the authentication middleware.</param>
        /// <returns></returns>
        private static HttpMessageHandler ResolveHttpMessageHandler(BungieAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator == null) return handler;
            // Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (webRequestHandler == null)
            {
                throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
            }
            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;

            return handler;
        }

        #endregion
    }
}