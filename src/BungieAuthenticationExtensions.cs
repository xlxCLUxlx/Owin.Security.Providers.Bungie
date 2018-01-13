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

namespace Owin.Security.Providers.Bungie
{
    /// <summary>
    /// Extension methods for using <see cref="BungieAuthenticationMiddleware"/>
    /// </summary>
    public static class BungieAuthenticationExtensions
    {
        #region Public Methods

        /// <summary>
        /// Authenticate users using Bungie.net
        /// </summary>
        /// <param name="app">The IAppBuilder passed to the configuration method.</param>
        /// <param name="options">Middleware configuration options.</param>
        /// <returns>The updated IAppBuilder</returns>
        public static IAppBuilder UseBungieAuthentication(this IAppBuilder app,
            BungieAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(BungieAuthenticationMiddleware), app, options);

            return app;
        }

        /// <summary>
        /// Authenticate users using Bungie.net
        /// </summary>
        /// <param name="app">The IAppBuilder passed to the configuration method.</param>
        /// <param name="clientId">The client id assigned by Bungie.net</param>
        /// <param name="clientSecret">The client secret assigned by Bungie.net</param>
        /// <param name="apiKey">The API key issued by the client portal.</param>
        /// <returns>The updated IAppBuilder</returns>
        public static IAppBuilder UseBungieAuthentication(this IAppBuilder app, string clientId, string clientSecret, string apiKey)
        {
            return app.UseBungieAuthentication(new BungieAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                ApiKey = apiKey
            });
        }

        #endregion
    }
}