[![Build status](https://ci.appveyor.com/api/projects/status/cy7622u2etdj7tl3?svg=true)](https://ci.appveyor.com/project/xlxCLUxlx/owin-security-providers-bungie)

# Owin.Security.Providers.Bungie
OAuth provider for the Bungie.net API using OWIN

If you prefer to not have to build the source code but would rather just use the assembly in your code you can download the compiled assembly from [NuGet](https://www.nuget.org/packages/Owin.Security.Providers.Bungie/).

I am currently in the process of writing up some documentation as well as providing a basic sample ASP.NET MVC site that can be used in conjunction with the OAuth provider for debugging and learning how to interact with the Bungie API via OAuth.  I will provide a sequence diagram of the OAUth process with Bungie based on [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749).

For now you can see the sequence diagram and I will fill in specific details around it.

![](https://i.imgur.com/HkLqzpx.png)

The sequence illustrated in the diagram above includes the following steps (Per RFC 6749):

    (A)  The client initiates the flow by directing the resource owner's
         user-agent to the authorization endpoint.  The client includes
         its client identifier, requested scope, local state, and a
         redirection URI to which the authorization server will send the
         user-agent back once access is granted (or denied).
         
    (B)  The authorization server authenticates the resource owner (via
         the user-agent) and establishes whether the resource owner
         grants or denies the client's access request.

    (C)  Assuming the resource owner grants access, the authorization
         server redirects the user-agent back to the client using the
         redirection URI provided earlier (in the request or during
         client registration).  The redirection URI includes an
         authorization code and any local state provided by the client
         earlier.

    (D)  The client requests an access token from the authorization
         server's token endpoint by including the authorization code
         received in the previous step.  When making the request, the
         client authenticates with the authorization server.  The client
         includes the redirection URI used to obtain the authorization
         code for verification.

    (E)  The authorization server authenticates the client, validates the
         authorization code, and ensures that the redirection URI
         received matches the URI used to redirect the client in
         step (C).  If valid, the authorization server responds back with
         an access token and, optionally, a refresh token.
