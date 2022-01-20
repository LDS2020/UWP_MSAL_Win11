using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Resources;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Globalization;
using Windows.UI.Xaml;
using muxc = Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.UI.Text;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=234238

namespace UWP_MSAL_Win11
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : muxc.Page
    {

        const string serviceEndpoint = "https://graph.microsoft.com/v1.0/";
        public static bool bDisplayedPermissions = false;

        public MainPage()
        {
            this.InitializeComponent();
            this.NavigationCacheMode = NavigationCacheMode.Required;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
        }

        private async void OnNavigationFailed(object sender, NavigationFailedEventArgs e)
        {
        }

 
        private async void TestMSAL_Click(object sender, RoutedEventArgs e)
        {
            cmdTestMSAL.IsEnabled = false;  // prevent the users initiating a 2nd request
            bool bSuccess = await TestMSALAuthentication();
            
            if (bSuccess)
            {
                lblConnectSuccess.Visibility = Visibility.Visible;
                lblConnectFailure.Visibility = Visibility.Collapsed;
            }
            else
            {
                lblLogoutSuccess.Visibility = Visibility.Collapsed;
                lblLogoutFailure.Visibility = Visibility.Visible;
            }
            cmdTestMSAL.IsEnabled = true;
        }

        private async Task<bool> TestMSALAuthentication()
        {
            bool bSuccess = false;
            bool bUserWantsToTryToConnect = true;
            string sErrorMessage = String.Empty;

            do
            {

                try
                {
                    AuthenticationHelperMSAL myAH = new AuthenticationHelperMSAL();
                    string sAccountType = string.Empty;
                    if ((bool)optConsumer.IsChecked)
                        sAccountType = "consumers";
                    else
                    {
                        if ((bool)optBusiness.IsChecked)
                            sAccountType = "organizations";
                        else
                            sAccountType = "common";
                    }

                    App.MyHttpClient = await myAH.AuthorizeClientMSALAsync(App.MSGraphScopes, sAccountType);

                    if (App.MyHttpClient == null)
                    {
                        muxc.ContentDialog InfoDialog = new muxc.ContentDialog();
                        InfoDialog.Title = "UWP_MSAL_Win11";
                        sErrorMessage = "Login failed." + System.Environment.NewLine + System.Environment.NewLine + "Do you want to try again?";
                        InfoDialog.Content = sErrorMessage;

                        muxc.ContentDialogResult InfoDialogAnswer = await InfoDialog.ShowAsync();
                        if (InfoDialogAnswer == muxc.ContentDialogResult.Primary)
                            bUserWantsToTryToConnect = true;
                        else
                            bUserWantsToTryToConnect = false;
                    }
                    else
                        bSuccess = true;
                }
                catch (Exception ex)
                {
                    // Tell the user the login failed, why and if they want to try again

                    muxc.ContentDialog InfoDialog = new muxc.ContentDialog();
                    InfoDialog.Title = "UWP_MSAL_Win11";

                    sErrorMessage = String.Format("Login failed: {0}", ex.Message) + System.Environment.NewLine + System.Environment.NewLine + "Do you want to try again?";

                    InfoDialog.Content = sErrorMessage;
                    InfoDialog.PrimaryButtonText = "Yes";
                    InfoDialog.SecondaryButtonText = "No";

                    muxc.ContentDialogResult InfoDialogAnswer = await InfoDialog.ShowAsync();
                    if (InfoDialogAnswer == muxc.ContentDialogResult.Primary)
                        bUserWantsToTryToConnect = true;
                    else
                        bUserWantsToTryToConnect = false;
                }
            } while (bUserWantsToTryToConnect && !bSuccess);

            return bSuccess;
        }

        private async void cmdLogout_Click(object sender, RoutedEventArgs e)
        {
            bool bSuccess = false;
            try
            {
                cmdLogout.IsEnabled = false;
                AuthenticationHelperMSAL myAH = new AuthenticationHelperMSAL();
                bSuccess = await myAH.SignOutMSAL();
            }
            catch (Exception ex)
            {
                bSuccess = false;
            }

            if (bSuccess)
            {
                lblLogoutSuccess.Visibility = Visibility.Visible;
                lblLogoutFailure.Visibility = Visibility.Collapsed;
            }
            else
            {
                lblLogoutSuccess.Visibility = Visibility.Collapsed;
                lblLogoutFailure.Visibility = Visibility.Visible;
            }

            cmdLogout.IsEnabled = true;
        }
    }
}
