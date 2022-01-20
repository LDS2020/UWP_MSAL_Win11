// Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license. See full license at the bottom of this file.
// borrowed from https://docs.microsoft.com/en-us/azure/active-directory/develop/tutorial-v2-windows-uwp

using System;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Windows.ApplicationModel.Resources;
using Windows.Globalization;
using Windows.Storage;
using Microsoft.Identity.Client;
using System.Collections.Generic;

namespace UWP_MSAL_Win11
{
    internal class AuthenticationHelperMSAL
    {
        // The Client ID is used by the application to uniquely identify itself to the v2.0 authentication endpoint.
        static string clientId = App.Current.Resources["ida:ClientID"].ToString();
        static string PublicClientRedirectUri = App.Current.Resources["ida:PublicClientRedirectUri"].ToString();
        //   - for any Work or School accounts, use organizations
        //   - for any Work or School accounts, or Microsoft personal account, use common
        //   - for Microsoft Personal account, use consumers
        static string sMSALauthority = String.Empty;
        static string sAADInstance = App.Current.Resources["ida:AADInstance"].ToString();
//                                       App.Current.Resources["ida:AccountType"].ToString();

        public IPublicClientApplication PublicClientApp { get; set; }

        public static string TokenForUser = null;

        // To authenticate to Microsoft Graph, the client needs to know its App ID URI.
        public const string ResourceUrl = "https://graph.microsoft.com/";
        public static DateTimeOffset Expiration;

        // Store account-specific settings so that the app can remember that a user has already signed in.
        public static ApplicationDataContainer _settings = ApplicationData.Current.RoamingSettings;


        public async Task<HttpClient> AuthorizeClientMSALAsync(string[] Scopes, string sAccountType)
        {
            AuthenticationResult authResult;
            HttpClient myHttpClient = new HttpClient();

            sMSALauthority = sAADInstance + sAccountType;

            try
            {
                TokenForUser = await GetTokenHelperMSALAsync(Scopes);

                if (TokenForUser == null)
                    myHttpClient = null;
                else
                    myHttpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + TokenForUser);
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return myHttpClient;
        }

        private void BuildPublicClientApp()
        {
            PublicClientApp = PublicClientApplicationBuilder.Create(clientId)
                    .WithAuthority(sMSALauthority)
                    .WithLogging(LogMSAL, LogLevel.Verbose, enableDefaultPlatformLogging: true)
                    .WithRedirectUri(PublicClientRedirectUri)
                    .WithUseCorporateNetwork(true)
                    .Build();
        }

        private static void LogMSAL(LogLevel level, string message, bool containsPii)
        {

            Debug.WriteLine($"MSAL: {level} {message} {containsPii}");
        }

        // Get an access token for the given context and resourceId. An attempt is first made to 
        // acquire the token silently. If that fails, then we try to acquire the token by prompting the user.
        public async Task<String> GetTokenHelperMSALAsync(string[] Scopes)
        {
            string TokenForUser = null;
            AuthenticationResult authResult;
            IAccount myAccount = null;

            try
            {
                BuildPublicClientApp();
                if (PublicClientApp == null)
                    throw new Exception("Cannot_authenticate"); 
                else
                {
                    authResult = null;

                    myAccount = await FindLastUsedAccountAsync();

                    Debug.WriteLine("GetTokenHelperMSALAsync: Attempt silent login");

                    if (myAccount != null)
                       authResult = await PublicClientApp.AcquireTokenSilent(Scopes, myAccount).ExecuteAsync();

                    // try again interactively 

                    if (authResult == null)
                    {
                        Debug.WriteLine("GetTokenHelperMSALAsync: Silent login failed. Requesting interactively");

                        authResult = await PublicClientApp.AcquireTokenInteractive(Scopes)
                        .WithPrompt(Prompt.SelectAccount)
                        .ExecuteAsync()
                        // It's good practice to not do work on the UI thread, so use ConfigureAwait(false) whenever possible.  
                        .ConfigureAwait(false);
                    }

                    // if it still didn't work report it. Most likely the method above threw an exception and we are now down in the Catch section

                    if (authResult == null)
                        throw new System.ArgumentException("cannot_authenticate");
                    else
                    {
                        if (!string.IsNullOrEmpty(authResult.AccessToken))
                        {
                            Debug.WriteLine("GetTokenHelperMSALAsync: Successful login");

                            TokenForUser = authResult.AccessToken;
                            // save user ID in local storage
                            _settings.Values["userEmail"] = authResult.Account.Username;
                            //   _settings.Values["userName"] = authResult.Account.Username;
                        }
                    }
                }
            }

            // there are many different reasons why this exception could have been thrown so just send back the error code
            // you can look up the error code in https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
            // and https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-handling-exceptions

            // once we have determined the most popular error codes we can create localized user friendly messages

            // we log more details in the calling code but we get full details now


            catch (Microsoft.Identity.Client.MsalUiRequiredException)
            {
                if (TokenForUser == null || Expiration <= DateTimeOffset.UtcNow.AddMinutes(5))
                {
                    authResult = null;
                    try
                    {
                        // try again interactively 
                        authResult = await PublicClientApp.AcquireTokenInteractive(Scopes)
                         .WithPrompt(Prompt.SelectAccount)
                         .ExecuteAsync()
                         .ConfigureAwait(false);
                    }

                    catch (Microsoft.Identity.Client.MsalServiceException ex)
                    {
                        try
                        {
                            CatchMsalServiceException(ex);
                        }
                        catch (Exception ex2)
                        {
                            throw ex2;
                        }
                    }

                    // These are the exceptions thrown when a user is entering the email address and password

                    catch (Microsoft.Identity.Client.MsalClientException ex)
                    {
                        try
                        {
                            CatchMsalClientException(ex);
                        }
                        catch (Exception ex2)
                        {
                            throw ex2;
                        }
                    }

                    catch (Microsoft.Identity.Client.MsalException ex)
                    {
                        throw ex;
                    }

                    catch (Exception ex)
                    {
                        throw ex;
                    }

                    TokenForUser = authResult.AccessToken;
                    Expiration = authResult.ExpiresOn;

                    // save user ID in local storage
                    _settings.Values["userEmail"] = authResult.Account.Username;
                    //   _settings.Values["userName"] = authResult.Account.Username;
                }
            }

            catch (Microsoft.Identity.Client.MsalServiceException ex)
            {
                try
                {
                    CatchMsalServiceException(ex);
                }
                catch (Exception ex2)
                {
                    throw ex2;
                }         
            }

            catch (Microsoft.Identity.Client.MsalClientException ex)
            {
                try
                {
                    CatchMsalClientException(ex);
                }
                catch (Exception ex2)
                {
                    throw ex2;
                }
            }

            catch (Microsoft.Identity.Client.MsalException ex)
            {
                throw ex;
            }

            catch (System.NotImplementedException ex)
            {
                throw ex;

            }
            catch (Exception ex)
            {
                throw ex;
            }

            return TokenForUser;
        }

        private void CatchMsalServiceException (Microsoft.Identity.Client.MsalServiceException ex)
        {
            throw new System.ArgumentException(ex.ErrorCode);
            /*
            if (ex.ErrorCode.Contains("access_denied"))                     // AADSTS50126: InvalidUserNameOrPassword 
                throw new System.ArgumentException("access_denied");
            else
            {
                if (ex.ErrorCode.Contains("The user has denied access"))    // AADSTS65004 - UserDeclinedConsent   
                    throw new System.ArgumentException("authentication_user_denied_access");
                else
                    throw ex;
            }
            */

        }

        private void CatchMsalClientException(Microsoft.Identity.Client.MsalClientException ex)
        {
            throw new System.ArgumentException(ex.ErrorCode);

            /*
            if (ex.ErrorCode.Contains("authentication_canceled"))
                throw new System.ArgumentException("authentication_canceled");
            else
                throw ex;
                */
        }

        /// <summary>
        /// Signs the user out of the service.
        /// </summary>
        public async Task<bool> SignOutMSAL()
        {
            bool bSuccess = false;

            try
            {
                BuildPublicClientApp();
                IAccount myAccount = await FindLastUsedAccountAsync();

                if (myAccount != null)
                    await PublicClientApp.RemoveAsync(myAccount);

                TokenForUser = null;

                //      Clear stored values from last authentication.
                //     _settings.Values["userID"] = null;
                _settings.Values["userEmail"] = null;
                //     _settings.Values["userName"] = null;

                bSuccess = true;
            }
            catch (Exception ex)
            {
                bSuccess = false;
                throw ex;
            }

            return bSuccess;
        }

        private async Task<IAccount> FindLastUsedAccountAsync()
        {
            IAccount myAccount = null;

            try
            {
                IEnumerable<IAccount> accounts = await PublicClientApp.GetAccountsAsync();

                string sEmailAddress = string.Empty;
                if (_settings.Values["userEmail"] != null)
                    sEmailAddress = _settings.Values["userEmail"].ToString();

                if (!string.IsNullOrEmpty(sEmailAddress))
                    foreach (IAccount anAccount in accounts)
                        if (anAccount.Username.Equals(sEmailAddress))
                        {
                            myAccount = anAccount;
                            break;
                        }

                if (myAccount == null)
                    myAccount = accounts.FirstOrDefault();
            }
            catch (Exception)
            {
                myAccount = null;
            }
            return myAccount;
        }

        /*
        public static string GetAppRedirectURI()
        {
            // Windows 10 universal apps require redirect URI in the format below. Add a breakpoint to this line, and run the app before you register it so that
            // you can supply the correct redirect URI value.
            return string.Format("ms-appx-web://microsoft.aad.brokerplugin/{0}", WebAuthenticationBroker.GetCurrentApplicationCallbackUri().Host).ToUpper();
        }
        */

     }
}

//********************************************************* 
// 
//O365-UWP-Microsoft-Graph-Snippets, https://github.com/OfficeDev/O365-UWP-Microsoft-Graph-Snippets
//
//Copyright (c) Microsoft Corporation
//All rights reserved. 
//
// MIT License:
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
//********************************************************* 