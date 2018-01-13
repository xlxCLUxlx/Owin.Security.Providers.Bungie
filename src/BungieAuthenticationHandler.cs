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
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Bungie
{
    public class BungieAuthenticationHandler : AuthenticationHandler<BungieAuthenticationOptions>
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
        /// Initializes a new instance of the <see cref="BungieAuthenticationHandler"/> class.
        /// </summary>
        /// <param name="httpClient">Used for sending HTTP request and receiving HTTP resposnses from a resource URI.</param>
        /// <param name="logger">Generic interface for OWIN logging.</param>
        public BungieAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Called once by common code after initialization. If an authentication middleware responds directly to
        /// specifically known paths it must override this function, compare the request path to it's known paths, 
        /// provide any response information as appropriate, and true to stop further processing.
        /// </summary>
        /// <returns>Returning false will cause the common code to call the next middleware in line. Returning true will
        /// cause the common code to begin the async completion journey without calling the rest of the middleware
        /// pipeline.</returns>
        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        #endregion

        #region Protected Methods

        /// <summary>
        /// Override this method to deal with 401 challenge concerns, if an authentication scheme in question
        /// deals an authentication interaction as part of it's request flow. (like adding a response header, or
        /// changing the 401 result to 302 of a login page or external sign-in location.)
        /// </summary>
        /// <returns>An asynchronous operation.</returns>
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null) return Task.FromResult<object>(null);
            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            var redirectUri =
                baseUri +
                Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var state = Options.StateDataFormat.Protect(properties);

            var authorizationEndpoint =
                Options.AuthorizationEndpoint +
                "?response_type=code" +
                "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&state=" + Uri.EscapeDataString(state);

            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// The core authentication logic which must be provided by the handler. Will be invoked at most
        /// once per request. Do not call directly, call the wrapping Authenticate method instead.
        /// </summary>
        /// <returns>The ticket data provided by the authentication logic</returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };

                // Request the token
                HttpResponseMessage tokenResponse =
                    await _httpClient.PostAsync(Options.TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                JObject response = JObject.Parse(text);
                string accessToken = response.Value<string>("access_token");
                string membershipId = response.Value<string>("membership_id");

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                if (string.IsNullOrWhiteSpace(membershipId))
                {
                    _logger.WriteWarning("MembershipId was not found");
                    return new AuthenticationTicket(null, properties);
                }

                // Get the Bungie.net user
                var userRequest = new HttpRequestMessage(HttpMethod.Get, string.Format("{0}{1}", Options.UserInfoEndpoint, membershipId));
                userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                userRequest.Headers.Add("X-API-Key", Options.ApiKey);
                var userResponse = await _httpClient.SendAsync(userRequest, Request.CallCancelled);

                userResponse.EnsureSuccessStatusCode();
                text = await userResponse.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(text);

                var context = new BungieAuthenticatedContext(Context, user, response)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!string.IsNullOrEmpty(context.ID))
                {
                        context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.ID,
                            ClaimValueTypes.String, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,
                        ClaimValueTypes.String, Options.AuthenticationType));
                }

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Called by <see cref="InvokeAsync" /> after initialization. If an authentication middleware responds directly to
        /// specifically known paths it must override this function, compare the request path to it's known paths, 
        /// provide any response information as appropriate, and true to stop further processing.
        /// </summary>
        /// <returns>Returning false will cause the common code to call the next middleware in line. Returning true will
        /// cause the common code to begin the async completion journey without calling the rest of the middleware
        /// pipeline.</returns>
        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;
            // TODO: error responses

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new BungieReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }
            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }

        #endregion
    }
}