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

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Bungie
{
    /// <summary>
    /// Represents the return endpoint context which provides context information to middleware providers. <see cref="Microsoft.Owin.Security.Provider.ReturnEndpointContext" />
    /// </summary>
    public class BungieReturnEndpointContext : ReturnEndpointContext
    {
        #region Constructors

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context">This wraps OWIN environment dictionary and provides strongly typed accessors. <see cref="Microsoft.Owin.IOwinContext"/></param>
        /// <param name="ticket">Contains user identity information as well as additional authentication state.  <see cref="Microsoft.Owin.Security.AuthenticationTicket"/></param>
        public BungieReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }

        #endregion
    }
}