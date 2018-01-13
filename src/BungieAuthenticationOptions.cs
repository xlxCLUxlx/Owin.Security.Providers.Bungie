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
using System.Net.Http;

using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Bungie
{
    /// <summary>
    /// Implementation of Base Options for all authentication middleware.  <see cref="Microsoft.Owin.Security.AuthenticationOptions"/>
    /// </summary>
    public class BungieAuthenticationOptions : AuthenticationOptions
    {
        #region Constructors

        /// <summary>
        ///     Initializes a new <see cref="BungieAuthenticationOptions" />
        /// </summary>
        public BungieAuthenticationOptions()
            : base("Bungie")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-bungie");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// The Bungie.net developer API key used to access their endpoints.
        /// </summary>
        public string ApiKey { get; set; }

        /// <summary>
        /// The Bungie.net authorization endpoint where the user is redirected to either grant or deny access.
        /// </summary>
        public string AuthorizationEndpoint
        {
            get { return Constants.AuthorizationEndpoint; }
        }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to Bungie.net.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>
        /// If this property is null then the default certificate checks are performed, 
        /// validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with Bungie.net.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with Bungie.
        /// </summary>
        /// <value>
        /// The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is empty.
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// Gets or sets the Bungie.net developer supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the Bungie.net developer supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IBungieAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IBungieAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// The Bungie.net endpoint which is used for granting acess and refresh tokens.
        /// </summary>
        public string TokenEndpoint
        {
            get { return Constants.TokenEndpoint; }
        }

        /// <summary>
        /// The Bungie.net API endpoint for getting basic user profile information.
        /// </summary>
        public string UserInfoEndpoint
        {
            get { return Constants.UserInfoEndpoint; }
        }

        #endregion
    }
}