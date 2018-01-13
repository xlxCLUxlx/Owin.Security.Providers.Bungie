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
namespace Owin.Security.Providers.Bungie
{
    /// <summary>
    /// A static class of constants.
    /// </summary>
    internal static class Constants
    {
        #region Fields

        /// <summary>
        /// The Bungie.net authorization endpoint where the user is redirected to either grant or deny access.
        /// </summary>
        public const string AuthorizationEndpoint = "https://www.bungie.net/en/oauth/authorize";

        /// <summary>
        /// The name of the default authentication type.
        /// </summary>
        public const string DefaultAuthenticationType = "Bungie";

        /// <summary>
        /// The Bungie.net endpoint which is used for granting acess and refresh tokens.
        /// </summary>
        public const string TokenEndpoint = "https://www.bungie.net/platform/app/oauth/token/";

        /// <summary>
        /// The Bungie.net API endpoint for getting basic user profile information.
        /// </summary>
        public const string UserInfoEndpoint = "https://www.bungie.net/Platform/User/GetBungieNetUserById/";

        #endregion
    }
}