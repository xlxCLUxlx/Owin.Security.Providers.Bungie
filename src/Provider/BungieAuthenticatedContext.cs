// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
/*
 * MIT License
 *
 * MODIFICATIONS MADE BY ERIC BOULDEN UNDER THE MIT LICENSE.
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
using System.Security.Claims;

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Bungie
{
    /// <summary>
    /// Represents a base context.  <see cref="Microsoft.Owin.Security.Provider.BaseContext"/>.
    /// Also contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class BungieAuthenticatedContext : BaseContext
    {
        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="BungieAuthenticatedContext"/> class.
        /// </summary>
        /// <param name="context">This wraps OWIN environment dictionary and provides strongly typed accessors.  <see cref="Microsoft.Owin.IOwinContext"/></param>
        /// <param name="user">Bungie.net user</param>
        /// <param name="accessToken">Bungie.net Access token.</param>
        /// <param name="expiresIn">Seconds until the access token expiration.</param>
        /// <param name="refreshToken">A token to refresh an access token by making a refresh request to the token endpoint.</param>
        /// <param name="refreshExpiresIn">econds until the refresh token expiration./param>
        public BungieAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expiresIn, string refreshToken, string refreshExpiresIn)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (int.TryParse(expiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            int refreshExpiresValue;
            if (int.TryParse(refreshExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out refreshExpiresValue))
            {
                RefreshExpiresIn = TimeSpan.FromSeconds(refreshExpiresValue);
            }

            ID = TryGetValue(user, "membershipId");
            Name = TryGetValue(user, "displayName");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BungieAuthenticatedContext"/> class.
        /// </summary>
        /// <param name="context">This wraps OWIN environment dictionary and provides strongly typed accessors.  <see cref="Microsoft.Owin.IOwinContext"/></param>
        /// <param name="user">The JSON-serialized Bungie user info</param>
        /// <param name="tokenResponse">The JSON-serialized token response Bungie</param>
        public BungieAuthenticatedContext(IOwinContext context, JObject user, JObject tokenResponse)
            : base(context)
        {
            User = user;
            TokenResponse = tokenResponse;
            if (tokenResponse != null)
            {
                AccessToken = tokenResponse.Value<string>("access_token");
                RefreshToken = tokenResponse.Value<string>("refresh_token");

                int expiresValue;
                if (Int32.TryParse(tokenResponse.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
                {
                    ExpiresIn = TimeSpan.FromSeconds(expiresValue);
                }

                int refreshExpiresValue;
                if (Int32.TryParse(tokenResponse.Value<string>("refresh_expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out refreshExpiresValue))
                {
                    RefreshExpiresIn = TimeSpan.FromSeconds(refreshExpiresValue);
                }
            }

            ID = TryGetValue(user, "Response", "membershipId");
            Name = TryGetValue(user, "Response", "displayName");
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Gets or sets the Bungie OAuth access token.
        /// </summary>
        public string AccessToken
        {
            get; private set;
        }

        /// <summary>
        /// Gets or sets the Bungie access token expiration time.
        /// </summary>
        public TimeSpan? ExpiresIn
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the membership id of the user.
        /// </summary>
        public string ID
        {
            get; private set;
        }

        /// <summary>
        /// Gets or sets a claims-based identity. <see cref="System.Security.Claims.ClaimsIdentity"/>
        /// </summary>
        public ClaimsIdentity Identity
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the display name for the user.
        /// </summary>
        public string Name
        {
            get; private set;
        }

        /// <summary>
        /// Gets or sets a dictionary used to store state values about the authentication session. <see cref="Microsoft.Owin.Security.AuthenticationProperties"/>
        /// </summary>
        public AuthenticationProperties Properties
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the Bungie refresh token expiration time.
        /// </summary>
        public TimeSpan? RefreshExpiresIn
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the Bungie OAuth refresh token.  This is only available when the RequestOfflineAccess property of <see cref="BungieAuthenticationOptions"/> is set to true
        /// </summary>
        public string RefreshToken
        {
            get; private set;
        }

        /// <summary>
        /// Token response from Bungie
        /// </summary>
        public JObject TokenResponse
        {
            get; private set;
        }

        /// <summary>
        /// Gets or sets the JSON deserialized Bungie.net User.GeneralUser.
        /// </summary>
        /// <remarks>
        /// Contains the Bungie.net User.GeneralUser obtained from the endpoint https://www.bungie.net/Platform/User/GetBungieNetUserById/{id}/
        /// Documentation for this endpoint can be found at https://bungie-net.github.io/multi/operation_get_User-GetBungieNetUserById.html#operation_get_User-GetBungieNetUserById
        /// </remarks>
        public JObject User
        {
            get; private set;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Get the given subProperty from a list property.
        /// </summary>
        /// <param name="jObject">The JSON object to get the value from.</param>
        /// <param name="propertyName">The list property name.</param>
        /// <param name="subProperty">The sub property of the list property to get the value for.</param>
        /// <returns>The value of the property in the JSON object.</returns>
        private static string TryGetFirstValue(JObject jObject, string propertyName, string subProperty)
        {
            JToken value;
            if (jObject.TryGetValue(propertyName, out value))
            {
                var array = JArray.Parse(value.ToString());
                if (array != null && array.Count > 0)
                {
                    var subObject = JObject.Parse(array.First.ToString());
                    if (subObject != null)
                    {
                        if (subObject.TryGetValue(subProperty, out value))
                        {
                            return value.ToString();
                        }
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Get the value given the property name.
        /// </summary>
        /// <param name="jObject">The JSON object to get the value from.</param>
        /// <param name="propertyName">The name of the property to get the value for.</param>
        /// <returns>The value of the property in the JSON object.</returns>
        private static string TryGetValue(JObject jObject, string propertyName)
        {
            JToken value;
            return jObject.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        /// <summary>
        /// Get the given subProperty from a property.
        /// </summary>
        /// <param name="jObject">The JSON object to get the value from.</param>
        /// <param name="propertyName">The parent property to get the subproperty from.</param>
        /// <param name="subProperty">The sub property of the parent property to get eh value for.</param>
        /// <returns>The value of the property in the JSON object.</returns>
        private static string TryGetValue(JObject jObject, string propertyName, string subProperty)
        {
            JToken value;
            if (jObject.TryGetValue(propertyName, out value))
            {
                var subObject = JObject.Parse(value.ToString());
                if (subObject != null && subObject.TryGetValue(subProperty, out value))
                {
                    return value.ToString();
                }
            }
            return null;
        }

        #endregion
    }
}