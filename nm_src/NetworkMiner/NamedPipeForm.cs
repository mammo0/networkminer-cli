using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Design;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetworkMiner {
    public partial class NamedPipeForm : Form {
        public class Settings {

            public class DirectoryEditor : UITypeEditor {
                public override UITypeEditorEditStyle GetEditStyle(ITypeDescriptorContext context) {
                    return UITypeEditorEditStyle.Modal;
                }

                public override object EditValue(ITypeDescriptorContext context, IServiceProvider provider, object value) {

                    using (FolderBrowserDialog dialog = new FolderBrowserDialog()) {
                        if (dialog.ShowDialog() == DialogResult.OK)
                            return dialog.SelectedPath.TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar;
                        else
                            return value;
                    }
                }
            }

            const string PIPE_PREFIX = @"\\.\pipe\";

            private string pipeName = "PacketCache";
            private string outputPath = System.IO.Path.GetTempPath();

            [DisplayName("Pipe Name")]
            [Description("Name of the named pipe on the local machine. Don't include the " + PIPE_PREFIX + " prefix. Popular PCAP-over-NamedPipe providers are PacketCache and RawCap.")]
            public string PipeName {
                get { return this.pipeName; }
                set {
                    if (value.StartsWith(PIPE_PREFIX, StringComparison.OrdinalIgnoreCase))
                        this.pipeName = value.Substring(PIPE_PREFIX.Length);
                    else if (value.StartsWith(@"\\"))
                        MessageBox.Show("This feature cannot read remote pipes");
                    else
                        this.pipeName = value;
                }
            }

            [DisplayName("Require Administrator Privileges")]
            public bool RequireAdministratorPrivileges { get; set; } = true;

            [DisplayName("Idle Timeout (seconds)")]
            public ushort IdleTimeoutSeconds { get; set; } = 60;

            [DisplayName("Capture Filter (BPF)")]
            [Description("The BPF text of the provided capture filter will be sent into the named pipe on start. Many PCAP-over-NamedPipe services don't support this feature.")]
            public string BPF { get; set; } = string.Empty;

            [DisplayName("Output Directory")]
            [EditorAttribute(typeof(DirectoryEditor), typeof(System.Drawing.Design.UITypeEditor))]
            public string OutputPath {
                get { return this.outputPath; }
                set {
                    if(System.IO.Directory.Exists(value)) {
                        this.outputPath = value.TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar;
                    }
                }
            }

        }

        private Settings settings;
        private NetworkMinerForm parentForm;
        private System.Globalization.NumberFormatInfo numberFormatInfo;
        public NamedPipeForm(NetworkMinerForm parentForm) {
            InitializeComponent();
            this.startReadNamedPipeButton.Click += async (_, _e) => await ReadNamedPipeAsync();
            this.settings = new Settings();
            this.settings.OutputPath = parentForm.OutputDirectory.FullName + "Captures" + System.IO.Path.DirectorySeparatorChar;
            this.namedPipeSettingsPropertyGrid.SelectedObject = settings;
            this.parentForm = parentForm;
            this.startReadNamedPipeButton.Focus();
            this.startReadNamedPipeButton.Select();

            this.numberFormatInfo = new System.Globalization.CultureInfo("sv-SE", false).NumberFormat;
            this.numberFormatInfo.NumberGroupSeparator = " ";
            this.numberFormatInfo.NumberGroupSizes = new int[] { 3 };
            this.numberFormatInfo.NumberDecimalDigits = 0;
        }

        private async Task ReadNamedPipeAsync() {
            string packetCachePcapFile = this.settings.OutputPath + "NamedPipe_" + DateTime.Now.Ticks / 10000000 + ".pcap";
            this.startReadNamedPipeButton.Enabled = false;
            
            this.namedPipeSettingsPropertyGrid.Enabled = false;
            long bytesRead = 0;
            try {
                using (SharedUtils.NamedPipeReader namedPipeReader = new SharedUtils.NamedPipeReader(this.settings.PipeName, packetCachePcapFile, this.settings.RequireAdministratorPrivileges, this.settings.BPF)) {
                    System.Threading.CancellationTokenSource tokenSource = new System.Threading.CancellationTokenSource();
                    this.FormClosing += (object sender, FormClosingEventArgs e) => tokenSource.Cancel();
                    var readerTask = namedPipeReader.ReadAllAsync(tokenSource.Token, settings.IdleTimeoutSeconds * 1000);
                    while(await Task.WhenAny(readerTask, Task.Delay(namedPipeReader.UpdateTimeMilliseconds)) != readerTask) {
                        bytesRead = namedPipeReader.BytesReadTotal;
                        this.bytesReadLabel.Text = "Bytes read: " + bytesRead.ToString("N", this.numberFormatInfo);
                    }
                    bytesRead = await readerTask;
                }
                if (bytesRead == 0)
                    MessageBox.Show("No data read from local named pipe");
            }
            catch (Win32Exception ex) {
                //we can end up here if powershell isn't installed or if youser doesn't authenticate as Admin
                await SharedUtils.Logger.LogAsync("Pipe Win32Exception: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                MessageBox.Show("Win32Exception when reading from named pipe:" + Environment.NewLine + ex.Message);
            }
            catch (System.IO.IOException ex) {
                await SharedUtils.Logger.LogAsync("Pipe IOException: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                MessageBox.Show("IOException when reading from named pipe:" + Environment.NewLine + ex.Message);
            }
            catch (TimeoutException ex) {
                await SharedUtils.Logger.LogAsync("Pipe TimeoutException: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                MessageBox.Show("TimeoutException when reading from named pipe:" + Environment.NewLine + ex.Message);
            }
            catch (Exception ex) {
                await SharedUtils.Logger.LogAsync("Pipe Exception: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                MessageBox.Show("Exception when reading from named pipe:" + Environment.NewLine + ex.Message);
            }

            if (bytesRead > 0) {
                this.parentForm.Invoke((MethodInvoker)delegate () { this.parentForm.LoadPcapFile(packetCachePcapFile, true, System.IO.FileShare.ReadWrite); });
            }
            
            this.Close();
        }

        [Obsolete]
        private void startReadNamedPipeButton_Click(object sender, EventArgs e) {
            this.startReadNamedPipeButton.Enabled = false;
            this.namedPipeSettingsPropertyGrid.Enabled = false;

            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.FileName = "powershell.exe";
            string packetCachePcapFile = System.IO.Path.GetTempPath() + "PCAP-over-NamedPipe_" + DateTime.Now.Ticks / 10000000 + ".pcap";
            SharedUtils.Logger.Log("Dumping PacketCache to " + packetCachePcapFile, SharedUtils.Logger.EventLogEntryType.Information);
            string direction = "In";
            if (!string.IsNullOrEmpty(this.settings.BPF))
                direction = "InOut";

            StringBuilder ps = new StringBuilder();
            ps.AppendLine("-NonInteractive -NoProfile -Command $pipeStream = new-object System.IO.Pipes.NamedPipeClientStream '.','" + this.settings.PipeName + "','" + direction + "';");
            ps.AppendLine("$file = New-Object IO.FileStream '" + packetCachePcapFile + "' ,'OpenOrCreate','Write','ReadWrite';");
            ps.AppendLine("try {");
            ps.AppendLine(" $pipeStream.Connect(" + this.settings.IdleTimeoutSeconds + ");");
            if (!string.IsNullOrEmpty(this.settings.BPF)) {
                ps.AppendLine(" $bpf = [Text.Encoding]::ASCII.GetBytes('"+ this.settings.BPF + "');");
                ps.AppendLine(" $pipeStream.Write($bpf, 0, $bpf.Length);");
            }
            ps.AppendLine(" $buffer = new-object byte[] 4096;");
            ps.AppendLine(" $n = $pipeStream.Read($buffer, 0, $buffer.Length);");
            ps.AppendLine(" while ($n -gt 0) {");
            ps.AppendLine("     $file.Write($buffer, 0, $n);");
            ps.AppendLine("     $n = $pipeStream.Read($buffer, 0, $buffer.Length);");
            ps.AppendLine(" }");
            ps.AppendLine("}");
            ps.AppendLine("finally {");
            ps.AppendLine(" $file.Close();");
            ps.AppendLine(" $pipeStream.Dispose();");
            ps.AppendLine("}");

           
            startInfo.Arguments = ps.ToString();
                
            //startInfo.RedirectStandardOutput = true;
            //startInfo.RedirectStandardError = true;
            //startInfo.UseShellExecute = false;
            startInfo.UseShellExecute = true;
            //startInfo.CreateNoWindow = false;
            startInfo.CreateNoWindow = true;
            if(this.settings.RequireAdministratorPrivileges)
                startInfo.Verb = "runas";
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.ErrorDialog = true;

            BackgroundWorker backgroundPacketCacheReader = new BackgroundWorker();
            backgroundPacketCacheReader.DoWork += (s2, e2) => this.RunProcessAndMonitorFileSize(e2, startInfo, packetCachePcapFile);
            backgroundPacketCacheReader.RunWorkerAsync();
            backgroundPacketCacheReader.RunWorkerCompleted += (_, ea) => { this.Close(); };
        }

        [Obsolete]
        private void RunProcessAndMonitorFileSize(DoWorkEventArgs e, System.Diagnostics.ProcessStartInfo startInfo, string packetCachePcapFile) {
            try {
                using (System.Diagnostics.Process process = new System.Diagnostics.Process()) {
                    process.StartInfo = startInfo;
                    process.Start();

                    TimeSpan timeout = TimeSpan.FromSeconds(this.settings.IdleTimeoutSeconds);
                    DateTime lastFileSizeUpdate = DateTime.Now;

                    long bytesRead = 0;
                    bool loadPcapFileInvoked = false;
                    while (!process.WaitForExit(this.settings.IdleTimeoutSeconds * 1000)) {

                        //process has not yet exited
                        if (System.IO.File.Exists(packetCachePcapFile)) {
                            System.IO.FileInfo fi = new System.IO.FileInfo(packetCachePcapFile);
                            if (fi.Length == bytesRead && lastFileSizeUpdate.Add(timeout) < DateTime.Now) {
                                SharedUtils.Logger.Log("Timed out reading from local PacketCache.", SharedUtils.Logger.EventLogEntryType.Warning);
                                MessageBox.Show("Timed out reading from local PacketCache.");
                                e.Cancel = true;
                                process.Close();
                                break;
                            }
                            if (fi.Length > bytesRead) {
                                bytesRead = fi.Length;
                                lastFileSizeUpdate = DateTime.Now;
                                if (!loadPcapFileInvoked && bytesRead > 1024 * 1024) {
                                    this.Invoke((MethodInvoker)delegate () { this.parentForm.LoadPcapFile(packetCachePcapFile, true, System.IO.FileShare.ReadWrite); });
                                    loadPcapFileInvoked = true;
                                }
                            }
                        }
                        else if (lastFileSizeUpdate.Add(timeout) < DateTime.Now) {
                            MessageBox.Show("Timed out reading from local PacketCache.");
                            e.Cancel = true;
                            process.Close();
                            break;
                        }
                    }
                    if (!process.HasExited || process.ExitCode != 0) {
                        e.Cancel = true;
                        MessageBox.Show("Could not read from local named pipe");
                    }
                    else if (!loadPcapFileInvoked) {
                        this.Invoke((MethodInvoker)delegate () { this.parentForm.LoadPcapFile(packetCachePcapFile, true, System.IO.FileShare.ReadWrite); });
                        loadPcapFileInvoked = true;
                    }

                }
            }
            catch (System.ComponentModel.Win32Exception ex) {
                SharedUtils.Logger.Log("Win32Exception when reading from local PacketCache: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                //we can end up here if powershell isn't installed or if youser doesn't authenticate as Admin
                MessageBox.Show("Win32Exception when reading from local PacketCache.");
                e.Cancel = true;
            }
            catch (System.IO.IOException ex) {
                SharedUtils.Logger.Log("IOException when reading from local PacketCache: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                MessageBox.Show("IOException when reading from local PacketCache.");
                e.Cancel = true;
            }
            catch (TimeoutException ex) {
                SharedUtils.Logger.Log("TimeoutException when reading from local PacketCache: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                MessageBox.Show("TimeoutException when reading from local PacketCache.");
                e.Cancel = true;
            }
            catch (Exception ex) {
                SharedUtils.Logger.Log("Exception when reading from local PacketCache: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                MessageBox.Show("Exception when reading from local PacketCache.");
                e.Cancel = true;
            }
        }

        private void Process_Exited(object sender, EventArgs e) {
            throw new NotImplementedException();
        }
    }
}
