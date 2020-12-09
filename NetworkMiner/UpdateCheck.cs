using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;

namespace NetworkMiner {
    public partial class UpdateCheck : Form {

        public static string CachedLocalVersionCode = null;
        public static Action CachedDownloadButtonAction = null;
        public static string HelpText { get; set; }

        public static void ShowNewVersionFormIfAvailableAsync(Form parentForm, Version localVersion, bool showMessageBoxIfNoUpdate = false) {
            byte[] extra = null;
            if (PacketParser.Utils.SystemHelper.IsRunningOnMono())
                extra = Encoding.ASCII.GetBytes("Mono");
            //public Version(int major, int minor, int build, int revision)
            if (CachedLocalVersionCode == null)
                ShowNewVersionFormIfAvailableAsync(parentForm, localVersion, "1" + localVersion.Major + localVersion.Minor + localVersion.Build, extra);
            else {
                ShowNewVersionFormIfAvailableAsync(parentForm, localVersion, CachedLocalVersionCode, extra, showMessageBoxIfNoUpdate);
            }
        }

        public Action DownloadButtonAction { get; set; }
        

        public static void ShowNewVersionFormIfAvailableAsync(Form parentForm, Version localVersion, string productCode, byte[] extra = null, bool showMessageBoxIfNoUpdate = false) {
            if (CachedLocalVersionCode == null)
                CachedLocalVersionCode = productCode;

            System.Threading.Tasks.Task.Factory.StartNew(() => {

                try {
                    Version latestVersion = SharedUtils.ApiUtils.GetLatestVersion(productCode, out string releasePost, out string downloadUrl);
                    if (latestVersion > localVersion) {
                        SharedUtils.Logger.Log("Newer version available: " + latestVersion.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                        //this throws System.Reflection.TargetInvocationException in Mono:
                        parentForm.Invoke(new Action(() => {
                            UpdateCheck form = new UpdateCheck(latestVersion.ToString(), releasePost, downloadUrl);
                            form.ShowDialog();
                        }));//end of invoke
                    }
                    else if(showMessageBoxIfNoUpdate) {
                        SharedUtils.Logger.Log("This is the latest version", SharedUtils.Logger.EventLogEntryType.Information);
                        parentForm.Invoke(new Action(() => {
                            MessageBox.Show("You are running the latest version of NetworkMiner (" + localVersion.ToString() + ")", "No update required");
                        }));
                    }

                }
                catch (System.Net.WebException wex) {
                    string errorMessage;
                    if (PacketParser.Utils.SystemHelper.IsRunningOnMono()) {
                        //https://stackoverflow.com/questions/47379163/c-sharp-mono-ssl-issue
                        //Mono JIT compiler version 4.2.1 and 4.6.2 do not support anything better than TLS 1.0
                        errorMessage = "Error checking for updates. The installed Mono version does not support TLS 1.2. " + wex.Message;
                        SharedUtils.Logger.Log(errorMessage, SharedUtils.Logger.EventLogEntryType.Information);
                    }
                    else {
                        errorMessage = "Error checking for updates: " + wex.GetType().ToString() + " : " + wex.Message;
                        SharedUtils.Logger.Log(errorMessage, SharedUtils.Logger.EventLogEntryType.Error);
                    }
                    if(showMessageBoxIfNoUpdate)
                        parentForm.Invoke(new Action(() => {
                            MessageBox.Show(errorMessage, "Error checking for updates");
                        }));
                }
                catch (Exception e) {
                    string errorMessage = "Error checking for updates: " + e.GetType().ToString() + " : " + e.Message;
                    SharedUtils.Logger.Log(errorMessage, SharedUtils.Logger.EventLogEntryType.Error);
                    if (showMessageBoxIfNoUpdate)
                        parentForm.Invoke(new Action(() => {
                            MessageBox.Show(errorMessage, "Error checking for updates");
                        }));
                }
            });//end of task
        }

        public UpdateCheck(string newVersion, string releasePost, string downloadUrl) {
            InitializeComponent();
            this.Text = "Version " + newVersion + " available";

            this.newVersionTextBox.Text = "There is a newer version of NetworkMiner available. Please update to version " + newVersion + ".";
            if(!String.IsNullOrEmpty(HelpText)) {
                this.newVersionTextBox.Text += Environment.NewLine + HelpText;
            }


            if (string.IsNullOrEmpty(releasePost))
                this.releaseNoteLinkLabel.Visible = false;
            else {
                this.releaseNoteLinkLabel.Visible = true;
                this.releaseNoteLinkLabel.Links.Add(0, this.releaseNoteLinkLabel.Text.Length, releasePost);
            }
            if (string.IsNullOrEmpty(downloadUrl)) {
                this.downloadButton.Enabled = false;
            }
            else {
                if (CachedDownloadButtonAction != null)
                    this.DownloadButtonAction = new Action(() => {
                        try {
                            CachedDownloadButtonAction.Invoke();
                            //this.Close();
                        }
                        catch(Exception e) {
                            SharedUtils.Logger.Log("Error invoking CachedDownloadButtonAction: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                            //System.Diagnostics.Process.Start(downloadUrl);
                            SharedUtils.SystemHelper.ProcessStart(downloadUrl);
                        }
                    });
                else
                    this.DownloadButtonAction = new Action(() => {
                        //System.Diagnostics.Process.Start(downloadUrl);
                        SharedUtils.SystemHelper.ProcessStart(downloadUrl);
                    });
                this.downloadButton.Enabled = true;
            }
        }

        private void linkClicked(object sender, LinkLabelLinkClickedEventArgs e) {
            //System.Diagnostics.Process.Start(e.Link.LinkData.ToString());
            SharedUtils.SystemHelper.ProcessStart(e.Link.LinkData.ToString());
        }

        private void downloadButton_Click(object sender, EventArgs e) {
            //System.Diagnostics.Process.Start(e.Link.LinkData.ToString());
            this.DownloadButtonAction?.Invoke();
        }

    }
}
