//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Collections.Concurrent;
using System.Linq;

using SharedUtils.Pcap;
using System.Text.RegularExpressions;

namespace NetworkMiner {
    public partial class NetworkMinerForm : Form {

        public static System.Collections.ObjectModel.ReadOnlyCollection<string> RecommendedMonoPackages = new System.Collections.ObjectModel.ReadOnlyCollection<string>(
            new string[] {
            "libmono-system-windows-forms4.0-cil",
            "libmono-system-web4.0-cil",
            "libmono-system-net4.0-cil",
            "libmono-system-runtime-serialization4.0-cil",
            "libmono-system-xml-linq4.0-cil"
        });

        internal class EncodingWrapper {
            private Encoding encoding;

            public Encoding Encoding { get { return this.encoding; } }

            internal EncodingWrapper(Encoding encoding) {
                this.encoding = encoding;
            }

            public override string ToString() {
                return encoding.HeaderName + " " + encoding.EncodingName;
            }
        }

        

        delegate void GenericStringCallback(string text);
        delegate void GenericIntCallback(int value);
        public delegate void AddCaseFileCallback(string fileFullPath, string filename);

        delegate int GetIntValueCallback();
        delegate void EmptyDelegateCallback();

        internal const int GUI_UPDATE_INTERVAL_MS = 300;//100ms => 13% CPU usage, 300ms => 6%, 1000ms => 2% CPU usage

        //private int nFilesReceived;
        private NetworkWrapper.ISniffer sniffer;
        private ImageList imageList;
        private PacketHandlerWrapper packetHandlerWrapper;
        private PacketParser.CleartextDictionary.WordDictionary dictionary;
        private int pcapFileReaderQueueSize = 1000;
        private System.Collections.Specialized.NameValueCollection aboutText;
        private string productLink = "http://www.netresec.com/?page=NetworkMiner";
        private ToolInterfaces.ISettingsForm settingsForm = null;
        private bool keywordWarningMessageShown = false;

        //private ToolStripMenuItem lastIpLookupToolStripMenuItem, lastDomainLookupToolStripMenuItem = null;
        List<ToolStripItem> hostMenuStripExtraItems, browsersMenuStripExtraItems, filesMenuStripExtraItems;
        public Func<System.Net.IPAddress, DateTime, ToolStripMenuItem> GetIpLookupToolStripMenuItem;
        public Func<string, ToolStripMenuItem> GetDomainLookupToolStripMenuItem;
        public Func<string, ToolStripMenuItem> GetUrlLookupToolStripMenuItem;
        public Func<string, ToolStripMenuItem> GetHashLookupToolStripMenuItem;
        public Func<string, ToolStripMenuItem> GetJa3HashLookupToolStripMenuItem;
        public Func<string, ToolStripMenuItem> GetSubmitFileToolStripMenuItem;
        

        //private NetworkWrapper.PacketReceivedHandler packetReceivedHandler = null;
        private SharedUtils.Pcap.PacketReceivedHandler packetReceivedHandler = null;

        //interfaces
        private ToolInterfaces.IReportGenerator reportGenerator = null;
        private ToolInterfaces.IColorHandler<System.Net.IPAddress> _ipColorHandler = null;
        private Func<System.Net.IPAddress, string> ipLocator = null;
        private ToolInterfaces.IDataExporterFactory dataExporterFactory = null;
        private ToolInterfaces.IPcapOverIpReceiverFactory pcapOverIpReceiverFactory = null;
        private ToolInterfaces.IHostDetailsGenerator hostDetailsGenerator = null;
        private ToolInterfaces.IDomainNameFilter domainNameFilter = null;
        private ToolInterfaces.IHttpTransactionTreeNodeHandler httpTransactionTreeNodeHandler = null;

        private Form upgradeCodeForm = null;
        private Form licenseSignatureForm = null;

        private List<PacketParser.Fingerprints.IOsFingerprinter> preloadedFingerprints = null;
        List<TreeView> treeViewsWithHostIcons;

        private PacketParser.PopularityList<string, List<PacketParser.FileTransfer.ReconstructedFile>> messageAttachments;

        private ConcurrentQueue<PacketParser.Frame> frameQueue;
        private ConcurrentQueue<string> cleartextQueue;
        private ConcurrentQueue<PacketParser.FileTransfer.ReconstructedFile> fileQueue;
        private ConcurrentQueue<PacketParser.Events.ParametersEventArgs> parametersQueue;
        private ConcurrentQueue<PacketParser.NetworkCredential> credentialQueue;
        private ConcurrentQueue<PacketParser.NetworkHost> hostQueue;
        private ConcurrentQueue<PacketParser.Events.HttpClientEventArgs> httpClientQueue;
        private ConcurrentQueue<PacketParser.Events.DnsRecordEventArgs> dnsQueue;
        private ConcurrentQueue<PacketParser.Events.AnomalyEventArgs> anomalyQueue;
        private ConcurrentQueue<PacketParser.Events.SessionEventArgs> sessionQueue;
        private ConcurrentQueue<PacketParser.Events.MessageEventArgs> messageQueue;
        private int _snifferBufferToolStripProgressBarNewValue;
        private ConcurrentDictionary<Control, string> controlTextDictionary;
        private ConcurrentQueue<PacketParser.Events.KeywordEventArgs> keywordQueue;
        private Dictionary<System.Net.NetworkInformation.PhysicalAddress, HashSet<NetworkHostTreeNode>> macToTreeNodeDictionary;//used to get "Siblings" for hosts with the same MAC (for example IPv4 and IPv6 addresses on the same PC)
        //private bool useRelativePathIfAvailable = false;
        private bool _verifyX509Certificates = false;


        private Timer guiUpdateTimer;

        //Settings
        //public int MaxFramesToShow = 1000;
        private GuiProperties _guiProperties;

        //private ListViewItem dragAndDropListViewItem = null;
        

        

        public event EventHandler GuiCleared;

        internal ConcurrentQueue<PacketParser.FileTransfer.ReconstructedFile> FileQueue { get { return this.fileQueue; } }
        internal ConcurrentQueue<PacketParser.Events.ParametersEventArgs> ParametersQueue { get { return this.parametersQueue; } }
        internal ConcurrentQueue<PacketParser.NetworkCredential> CredentialQueue { get { return this.credentialQueue; } }
        internal ConcurrentQueue<PacketParser.NetworkHost> HostQueue { get { return this.hostQueue; } }
        internal ConcurrentQueue<PacketParser.Events.HttpClientEventArgs> HttpClientQueue { get { return this.httpClientQueue; } }
        internal ConcurrentQueue<PacketParser.Events.DnsRecordEventArgs> DnsQueue { get { return this.dnsQueue; } }
        internal ConcurrentQueue<PacketParser.Events.AnomalyEventArgs> AnomalyQueue { get { return this.anomalyQueue; } }
        internal ConcurrentQueue<PacketParser.Events.SessionEventArgs> SessionQueue { get { return this.sessionQueue; } }
        internal ConcurrentQueue<PacketParser.Events.MessageEventArgs> MessageQueue { get { return this.messageQueue; } }
        internal ConcurrentQueue<PacketParser.Events.KeywordEventArgs> KeywordQueue { get { return this.keywordQueue; } }
        //internal ConcurrentQueue<PacketParser.AudioStream> AudioStreamQueue { get; }
        //internal ConcurrentQueue<Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, string, string, string>> VoipCallQueue { get; }

        //internal List<string> SupportedCaptureFileExtensions { get; }

        public ToolInterfaces.IDataExporterFactory DataExporterFactory {
            get { return this.dataExporterFactory; }
            set {
                this.dataExporterFactory = value;
                if (this.dataExporterFactory != null) {
                    
                    this.exportToolStripMenuItem.Enabled = true;
                    this.exportToolStripMenuItem.Visible = true;
                }
                else {
                    this.exportToolStripMenuItem.Enabled = false;
                    this.exportToolStripMenuItem.Visible = false;
                }
            }
        }

        internal int SnifferBufferToolStripProgressBarNewValue {
            get {
                return this._snifferBufferToolStripProgressBarNewValue;
            }
            set {
                if (this._snifferBufferToolStripProgressBarNewValue != value)
                    this._snifferBufferToolStripProgressBarNewValue = value;
            }
        }

        public ToolInterfaces.IColorHandler<System.Net.IPAddress> IpColorHandler
        {
            get { return this._ipColorHandler; }
            set { this._ipColorHandler = value; }
        }

        public GuiProperties GuiProperties
        {
            get { return this._guiProperties; }
            set
            {
                this._guiProperties = value;

                if (this._guiProperties.UseCleartextTab != this.tabControl.TabPages.Contains(this.tabPageCleartext)) {
                    this.loadCleartextDictionary((string)this.dictionaryNameLabel.Tag, this._guiProperties.UseCleartextTab);
                }

                this.setTabPageVisibility(this.tabPageDetectedHosts, this._guiProperties.UseHostsTab);
                this.setTabPageVisibility(this.tabPageBrowsers, this._guiProperties.UseBrowsersTab);
                this.setTabPageVisibility(this.tabPageFiles, this._guiProperties.UseFilesTab);
                this.setTabPageVisibility(this.tabPageImages, this._guiProperties.UseImagesTab);
                this.setTabPageVisibility(this.tabPageMessages, this._guiProperties.UseMessagesTab);
                this.setTabPageVisibility(this.tabPageCredentials, this._guiProperties.UseCredentialsTab);
                this.setTabPageVisibility(this.tabPageVoIP, this._guiProperties.UseVoipTab);
                this.setTabPageVisibility(this.tabPageSessions, this._guiProperties.UseSessionsTab);
                this.setTabPageVisibility(this.tabPageDns, this._guiProperties.UseDnsTab);
                this.setTabPageVisibility(this.tabPageParameters, this._guiProperties.UseParametersTab);
                this.setTabPageVisibility(this.tabPageKeywords, this._guiProperties.UseKeywordsTab);
                this.setTabPageVisibility(this.tabPageCleartext, this._guiProperties.UseCleartextTab);
                this.setTabPageVisibility(this.tabPageReceivedFrames, this._guiProperties.UseFramesTab);
                this.setTabPageVisibility(this.tabPageAnomalyLog, this._guiProperties.UseAnomaliesTab);

                

            }
        }
        public System.IO.DirectoryInfo OutputDirectory
        {
            get { return new System.IO.DirectoryInfo(this.packetHandlerWrapper.PacketHandler.OutputDirectory); }
            set { this.CreateNewPacketHandlerWrapper(value); }
        }
        public bool DefangExecutableFiles
        {
            get { return this.packetHandlerWrapper.PacketHandler.DefangExecutableFiles; }
            set { this.packetHandlerWrapper.PacketHandler.DefangExecutableFiles = value; }
        }

        public bool ExtractPartialDownloads
        {
            get { return this.packetHandlerWrapper.PacketHandler.ExtractPartialDownloads; }
            set { this.packetHandlerWrapper.PacketHandler.ExtractPartialDownloads = value; }
        }

        public bool UseRelativeExtractedFilesPaths { set; get; } = true;

        public bool VerifyX509Certificates {
            get {
                return this._verifyX509Certificates;
            }
            set {
                if (this._verifyX509Certificates != value) {
                    this._verifyX509Certificates = value;
                    this.CreateNewPacketHandlerWrapper(this.OutputDirectory);
                }
            }
        }

        //properties
        public IEnumerable<CaseFile> CaseFiles
        {
            get
            {
                foreach (ListViewItem item in this.casePanelFileListView.Items)
                    if (item.Tag != null)
                        yield return (CaseFile)item.Tag;
            }
        }
        public PacketHandlerWrapper PacketHandlerWrapper { get { return this.packetHandlerWrapper; } }

        public ToolInterfaces.ISettingsForm SettingsForm
        {
            set
            {
                this.settingsForm = value;
                if (this.settingsForm != null) {
                    this.settingsToolStripMenuItem.Click += new EventHandler(settingsToolStripMenuItem_Click);
                    this.settingsToolStripMenuItem.Enabled = true;
                    this.settingsToolStripMenuItem.Visible = true;
                }
                else {
                    this.settingsToolStripMenuItem.Enabled = false;
                    this.settingsToolStripMenuItem.Visible = false;
                }
            }
        }
        public ToolInterfaces.IVoipCallHandler VoipCallHandler { get; set; }


        public NetworkMinerForm(string applicationTitle, int pcapFileReaderQueueSize, Func<System.Net.IPAddress, string> ipLocator, System.Collections.Specialized.NameValueCollection aboutText, ToolInterfaces.IDataExporterFactory dataExporterFactory, /*ToolInterfaces.IPcapOverIpReceiverFactory pcapOverIpReceiverFactory, */ToolInterfaces.IHostDetailsGenerator hostDetailsGenerator, NetworkMiner.ToolInterfaces.IDomainNameFilter domainNameFilter, string productLink, bool showWinPcapAdapterMissingError, Form upgradeCodeForm, Form licenseSignatureForm, List<PacketParser.Fingerprints.IOsFingerprinter> preloadedFingerprints, ToolInterfaces.IHttpTransactionTreeNodeHandler httpClientTreeNodeFactory)
            : this(showWinPcapAdapterMissingError, false) {
            this.Text = applicationTitle;
            this.pcapFileReaderQueueSize = pcapFileReaderQueueSize;
            //this.ipColorHandler = ipColorHandler; <-- this one will be set when the SettingsForm is initiated
            this.ipLocator = ipLocator;
            this.domainNameFilter = domainNameFilter;
            this.aboutText.Add(aboutText);
            this.DataExporterFactory = dataExporterFactory;
            if (this.DataExporterFactory != null) {
                this.DataExporterFactory.RegisterHandlers(this.packetHandlerWrapper.PacketHandler);//must be done after CreateNewPacketHandlerWrapper 
                this.GuiCleared += this.DataExporterFactory.ResetEventHandler;
            }

            //this.dataExporterFactory = dataExporterFactory;
            this.hostDetailsGenerator = hostDetailsGenerator;
            this.httpTransactionTreeNodeHandler = httpClientTreeNodeFactory;
            if (this.httpTransactionTreeNodeHandler != null) {
                this.httpTransactionTreeNodeHandler.SetNetworkMinerForm(this);
                this.httpTransactionTreeView.Nodes.Clear();
            }

            if (hostDetailsGenerator != null) {
                this.toolStripSeparator2.Visible = true;
                this.downloadRIPEDBToolStripMenuItem.Enabled = true;
                this.downloadRIPEDBToolStripMenuItem.Visible = true;
                this.downloadRIPEDBToolStripMenuItem.Click += new EventHandler(downloadRIPEDBToolStripMenuItem_Click);
            }
            else {
                this.toolStripSeparator2.Visible = false;
                this.downloadRIPEDBToolStripMenuItem.Enabled = false;
                this.downloadRIPEDBToolStripMenuItem.Visible = false;
            }


            /*
             if (this.dataExporterFactory != null) {
                this.exportToolStripMenuItem.Enabled = true;
                this.exportToolStripMenuItem.Visible = true;
            }
            */

            this.productLink = productLink;

            this.upgradeCodeForm = upgradeCodeForm;
            if (this.upgradeCodeForm != null) {
                this.getUpgradeCodeToolStripMenuItem.Enabled = true;
                this.getUpgradeCodeToolStripMenuItem.Visible = true;
                this.toolStripSeparator1.Visible = true;
            }
            this.licenseSignatureForm = licenseSignatureForm;
            if (this.licenseSignatureForm != null) {
                this.signWithLicenseToolStripMenuItem.Enabled = true;
                this.signWithLicenseToolStripMenuItem.Visible = true;
                this.toolStripSeparator1.Visible = true;
            }

            if (preloadedFingerprints != null) {
                this.preloadedFingerprints = preloadedFingerprints;
                //we must recreate the PacketHandlerWrapper with the updated fingerprints
                this.CreateNewPacketHandlerWrapper(new System.IO.DirectoryInfo(System.IO.Path.GetDirectoryName(System.Windows.Forms.Application.ExecutablePath)));
            }


            
            this.loadCleartextDictionary((string)this.dictionaryNameLabel.Tag, this.GuiProperties.UseCleartextTab);
            
            
        }






        public NetworkMinerForm() : this(false, true) {

        }

        public NetworkMinerForm(bool showWinPcapAdapterMissingError, bool removeBrowsersAndVoipTab) {
            this.frameQueue = new ConcurrentQueue<PacketParser.Frame>();
            this.fileQueue = new ConcurrentQueue<PacketParser.FileTransfer.ReconstructedFile>();
            this.parametersQueue = new ConcurrentQueue<PacketParser.Events.ParametersEventArgs>();
            this.cleartextQueue = new ConcurrentQueue<string>();
            this.credentialQueue = new ConcurrentQueue<PacketParser.NetworkCredential>();
            this.hostQueue = new ConcurrentQueue<PacketParser.NetworkHost>();
            this.httpClientQueue = new ConcurrentQueue<PacketParser.Events.HttpClientEventArgs>();
            this.dnsQueue = new ConcurrentQueue<PacketParser.Events.DnsRecordEventArgs>();
            this.anomalyQueue = new ConcurrentQueue<PacketParser.Events.AnomalyEventArgs>();
            this.sessionQueue = new ConcurrentQueue<PacketParser.Events.SessionEventArgs>();
            this.messageQueue = new ConcurrentQueue<PacketParser.Events.MessageEventArgs>();
            this.keywordQueue = new ConcurrentQueue<PacketParser.Events.KeywordEventArgs>();
            this.aboutText = new System.Collections.Specialized.NameValueCollection();
            this.macToTreeNodeDictionary = new Dictionary<System.Net.NetworkInformation.PhysicalAddress, HashSet<NetworkHostTreeNode>>();
            //this.AudioStreamQueue = new ConcurrentQueue<PacketParser.AudioStream>();
            //this.VoipCallQueue = new ConcurrentQueue<Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, string, string, string>>();

            this.controlTextDictionary = new ConcurrentDictionary<Control, string>();
            this.guiUpdateTimer = new Timer();
            this.guiUpdateTimer.Interval = GUI_UPDATE_INTERVAL_MS;//40 ms interval => 25 GUI updates/s
            this.guiUpdateTimer.Tick += this.GuiUpdateTimer_Tick;

            if (SharedUtils.Logger.CurrentLogLevel == SharedUtils.Logger.LogLevel.Debug && SharedUtils.Logger.LogToFile) {
#if !DEBUG                
                MessageBox.Show("Writing debug log to: " + SharedUtils.Logger.LogFilePath);
#endif
            }

            SharedUtils.Logger.Log("Initializing Component", SharedUtils.Logger.EventLogEntryType.Information);
            InitializeComponent();
            SharedUtils.Logger.Log("Component Initialized", SharedUtils.Logger.EventLogEntryType.Information);
            this.hostMenuStripExtraItems = new List<ToolStripItem>();
            this.browsersMenuStripExtraItems = new List<ToolStripItem>();
            this.filesMenuStripExtraItems = new List<ToolStripItem>();
            this.GetIpLookupToolStripMenuItem = new Func<System.Net.IPAddress, DateTime, ToolStripMenuItem>((ip, date) => {
                ToolStripMenuItem notAvailable = new ToolStripMenuItem("OSINT lookup of " + ip + "isn't available in the free version");
                notAvailable.Enabled = false;
                return notAvailable;
            });
            this.GetDomainLookupToolStripMenuItem = new Func<string, ToolStripMenuItem>((d) => {
                ToolStripMenuItem notAvailable = new ToolStripMenuItem("OSINT lookup of " + d + " isn't available in the free version");
                notAvailable.Enabled = false;
                return notAvailable;
            });
            this.GetUrlLookupToolStripMenuItem = new Func<string, ToolStripMenuItem>((u) => {
                ToolStripMenuItem notAvailable = new ToolStripMenuItem("OSINT lookup of " + u + " isn't available in the free version");
                notAvailable.Enabled = false;
                return notAvailable;
            });
            this.GetHashLookupToolStripMenuItem = new Func<string, ToolStripMenuItem>((p) => {
                ToolStripMenuItem notAvailable = new ToolStripMenuItem("OSINT hash lookup isn't available in the free version");
                notAvailable.Enabled = false;
                return notAvailable;
            });
            this.GetJa3HashLookupToolStripMenuItem = new Func<string, ToolStripMenuItem>((ja3) => {
                ToolStripMenuItem notAvailable = new ToolStripMenuItem("OSINT JA3 hash lookup isn't available in the free version");
                notAvailable.Enabled = false;
                return notAvailable;
            });
            this.GetSubmitFileToolStripMenuItem = new Func<string, ToolStripMenuItem>((p) => {
                ToolStripMenuItem notAvailable = new ToolStripMenuItem("Sample submision isn't available in the free version");
                notAvailable.Enabled = false;
                return notAvailable;
            });
            SharedUtils.Logger.Log("Requiring File IO Permissions", SharedUtils.Logger.EventLogEntryType.Information);
            try {
                //require FileIOPermission to be PermissionState.Unrestricted
                System.Security.Permissions.FileIOPermission fileIOPerm = new System.Security.Permissions.FileIOPermission(System.Security.Permissions.PermissionState.Unrestricted);
                fileIOPerm.Demand();
            }
            catch (System.Security.SecurityException ex) {
                SharedUtils.Logger.Log(ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                MessageBox.Show("Make sure you are not running NetworkMiner from a network share!\n\nIf you need to run NetworkMiner from a non-trusted location (like a network share), then use Caspol.exe or Mscorcfg.msc to grant NetworkMiner full trust.", "File Permission Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                //Application.Exit();
                throw ex;
            }
            try {
                //require FileIOPermission to be PermissionState.Unrestricted
                string path = System.IO.Path.GetDirectoryName(System.Windows.Forms.Application.ExecutablePath) + System.IO.Path.DirectorySeparatorChar + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY;
                System.Security.Permissions.FileIOPermission fileIOPerm = new System.Security.Permissions.FileIOPermission(System.Security.Permissions.FileIOPermissionAccess.AllAccess, path);
                fileIOPerm.Demand();
            }
            catch (System.Security.SecurityException ex) {
                SharedUtils.Logger.Log(ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                DialogResult result = MessageBox.Show("Please ensure that the user has write permissions in the AssembledFiles directory." + Environment.NewLine + Environment.NewLine + ex.Message, "Unauthorized Access", MessageBoxButtons.OK, MessageBoxIcon.Error);
                throw ex;
            }
            /*
            this.SupportedCaptureFileExtensions = new List<string>() { 
                "pcap",
                "cap",
                "dump",
                "dmp",
                "eth",
                "log"
            };
            */

            SharedUtils.Logger.Log("Checking for Mono", SharedUtils.Logger.EventLogEntryType.Information);
            if (SharedUtils.SystemHelper.IsRunningOnMono()) {
                SharedUtils.Logger.Log("Mono detected", SharedUtils.Logger.EventLogEntryType.Information);
                try {
                    string s = PacketParser.FileTransfer.FileStreamAssembler.UrlEncode("Verifying that System.Web can be referenced properly");
                }
                catch (System.IO.FileNotFoundException e) {
                    SharedUtils.Logger.Log(e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine("Please install the following packages from the Mono Project:");
                    foreach (string p in RecommendedMonoPackages)
                        sb.AppendLine(p);
                    MessageBox.Show(sb.ToString(), "System.Web assembly is missing");
                    SharedUtils.Logger.Log(sb.ToString().Replace(Environment.NewLine, " "), SharedUtils.Logger.EventLogEntryType.Error);
                    throw e;
                }
                try {
                    System.Net.WebRequest request = System.Net.WebRequest.Create("https://localhost");
                }
                catch (System.IO.FileNotFoundException e) {
                    SharedUtils.Logger.Log(e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine("Please install the following packages from the Mono Project:");
                    foreach (string p in RecommendedMonoPackages)
                        sb.AppendLine(p);
                    MessageBox.Show(sb.ToString(), "System.Net assembly is missing");
                    SharedUtils.Logger.Log(sb.ToString().Replace(Environment.NewLine, " "), SharedUtils.Logger.EventLogEntryType.Error);
                    throw e;
                }
                try {
                    //In Mono, there is no Windows Certificate store. Mono has it's own store. By default, it is empty (there are no default CA's that are trusted).
                    //http://www.mono-project.com/archived/usingtrustedrootsrespectfully/
                    //https://stackoverflow.com/questions/4926676/mono-https-webrequest-fails-with-the-authentication-or-decryption-has-failed/33391290
                    
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(
                        (o, cert, chain, policyErrors) => {
                            SharedUtils.Logger.Log("Performing custom SSL validation for Mono", SharedUtils.Logger.EventLogEntryType.Information);
                            //Return true if the server certificate is ok
                            if (policyErrors == System.Net.Security.SslPolicyErrors.None)
                                return true;
                            else if (policyErrors == System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable) {
                                SharedUtils.Logger.Log("SSL validation error: " + policyErrors.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                                return false;
                            }

                            else if (policyErrors == System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) {
                                SharedUtils.Logger.Log("SSL validation error: " + policyErrors.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                                return false;
                            }
                            else if (policyErrors == System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) {
                                foreach (var item in chain.ChainStatus) {
                                    if (item.Status == System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.PartialChain) {
                                        SharedUtils.Logger.Log("Ignoring SSL Chain Status validation error: " + item.Status.ToString() + " for " + item.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                                    }
                                    else if (item.Status != System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.NoError) {
                                        SharedUtils.Logger.Log("SSL Chain Status validation error: " + item.Status.ToString() + " for " + item.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                                        return false;
                                    }
                                }
                            }
                            return true;
                        }
                    );
                }
                catch(Exception e) {
                    SharedUtils.Logger.Log("Error disabling SSL verification in Mono " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                }

                //Avoid showing sniffing features when running under Mono
                int yDiff = this.splitContainer1.Location.Y - this.networkAdaptersComboBox.Location.Y;
                //this.splitContainer1.Location = new Point(this.splitContainer1.Location.X, this.networkAdaptersComboBox.Location.Y);//move up
                this.splitContainer1.Location = new Point(this.splitContainer1.Location.X, this.splitContainer1.Location.Y - yDiff);//move up
                this.splitContainer1.Height = this.splitContainer1.Height + yDiff;
                this.networkAdaptersComboBox.Visible = false;
                this.button2.Visible = false;
                this.startButton.Visible = false;
                this.stopButton.Visible = false;
                this.startCapturingToolStripMenuItem.Visible = false;
                this.stopCapturingToolStripMenuItem.Visible = false;
                this.toolStripSeparator3.Visible = false;

                //this.snifferBufferToolStripProgressBar.Visible = false;
                //this.toolStripStatusLabel1.Text = "Running NetworkMiner with Mono";
                this.readFromPacketCacheToolStripMenuItem.Visible = false;


            }

            ContextMenuStrip fileCommandStrip = new ContextMenuStrip(this.components);
            fileCommandStrip.Items.Add(new ToolStripMenuItem("Open file", null, new EventHandler(this.OpenFile_Click)));

            fileCommandStrip.Items.Add(new ToolStripMenuItem("Open folder", global::NetworkMiner.Properties.Resources.openHS, new EventHandler(this.OpenFileFolder_Click)));
            fileCommandStrip.Items.Add(new ToolStripMenuItem("Copy path to clipboard", null, new EventHandler(this.CopySelectedListViewItemTagToClipBoard)));
            fileCommandStrip.Items.Add(new ToolStripMenuItem("File details", null, new EventHandler(this.ShowFileDetails)));
            //toolstripseparator
            fileCommandStrip.Items.Add(new ToolStripSeparator());
            fileCommandStrip.Items.Add(new ToolStripMenuItem("Auto-resize all columns", null, new EventHandler(autoResizeFileColumns_Click)));
            this.filesListView.ContextMenuStrip = fileCommandStrip;

            ContextMenuStrip attachmentCommandStrip = new ContextMenuStrip(this.components);
            attachmentCommandStrip.Items.Add(new ToolStripMenuItem("Open file", null, new EventHandler(OpenAttachment_Click)));
            attachmentCommandStrip.Items.Add(new ToolStripMenuItem("Open folder", null, new EventHandler(OpenAttachmentFolder_Click)));
            this.messageAttachmentListView.ContextMenuStrip = attachmentCommandStrip;

            ContextMenuStrip credentialCommandStrip = new ContextMenuStrip(this.components);
            credentialCommandStrip.Items.Add(new ToolStripMenuItem("Copy Username", null, new EventHandler(CopyCredentialUsernameToClipboard_Click)));
            credentialCommandStrip.Items.Add(new ToolStripMenuItem("Copy Password", null, new EventHandler(CopyCredentialPasswordToClipboard_Click)));
            credentialCommandStrip.Items.Add(new ToolStripMenuItem("Auto-resize all columns", null, new EventHandler(autoResizeCredentialsColumns_Click)));
            this.credentialsListView.ContextMenuStrip = credentialCommandStrip;

            this.parametersContextMenuStrip.Items.Add(new ToolStripMenuItem("Auto-resize all columns", null, new EventHandler(autoResizeParameterColumns_Click)));

            ContextMenuStrip imageCommandStrip = new ContextMenuStrip(this.components);
            imageCommandStrip.Items.Add(new ToolStripMenuItem("Open image", null, new EventHandler(OpenImage_Click)));
            ToolStripMenuItem imageZoomInItem1 = new ToolStripMenuItem("Zoom in", null, new EventHandler(ImageZoomIn), Keys.Control | Keys.Oemplus);
            ToolStripMenuItem imageZoomInItem2 = new ToolStripMenuItem("Zoom in", null, new EventHandler(ImageZoomIn), Keys.Control | Keys.Add);
            imageZoomInItem1.ShortcutKeyDisplayString = "Ctrl + '+'";
            imageZoomInItem2.Visible = false;
            imageCommandStrip.Items.Add(imageZoomInItem1);
            imageCommandStrip.Items.Add(imageZoomInItem2);

            ToolStripMenuItem imageZoomOutItem1 = new ToolStripMenuItem("Zoom out", null, new EventHandler(ImageZoomOut), Keys.Control | Keys.OemMinus);
            ToolStripMenuItem imageZoomOutItem2 = new ToolStripMenuItem("Zoom out", null, new EventHandler(ImageZoomOut), Keys.Control | Keys.Subtract);
            imageZoomOutItem1.ShortcutKeyDisplayString = "Ctrl + '-'";
            imageZoomOutItem2.Visible = false;
            imageCommandStrip.Items.Add(imageZoomOutItem1);
            imageCommandStrip.Items.Add(imageZoomOutItem2);
            this.imagesListView.ContextMenuStrip = imageCommandStrip;

            this.CreateNewPacketHandlerWrapper(new System.IO.DirectoryInfo(System.IO.Path.GetDirectoryName(System.Windows.Forms.Application.ExecutablePath)));

            this.imagesListView.View = View.LargeIcon;
            this.imageList = new ImageList();
            this.imageList.ImageSize = new Size(64, 64);
            this.imageList.ColorDepth = ColorDepth.Depth32Bit;
            this.imagesListView.LargeImageList = imageList;



            //this.networkAdaptersComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.hostSortOrderComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.hostSortOrderComboBox.SelectedIndex = 0;
            this.cleartextSearchModeComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cleartextSearchModeComboBox.SelectedIndex = 1;//Search TCP and UDP payload

            

            List<NetworkWrapper.IAdapter> networkAdapters = new List<NetworkWrapper.IAdapter>();
            networkAdapters.Add(new NetworkWrapper.NullAdapter());

            SharedUtils.Logger.Log("Checking for possible DLL injections", SharedUtils.Logger.EventLogEntryType.Information);
            List<string> dllDirectories = new List<string>();
            List<string> winPcapDllFiles = new List<string>();
            dllDirectories.Add(Environment.CurrentDirectory);
            dllDirectories.Add(System.Windows.Forms.Application.ExecutablePath);
            dllDirectories.Add(System.Windows.Forms.Application.StartupPath);
            winPcapDllFiles.Add("wpcap.dll");
            winPcapDllFiles.Add("packet.dll");
            string hijackedPath;
            if (NetworkWrapper.Utils.Security.DllHijackingAttempted(dllDirectories, winPcapDllFiles, out hijackedPath)) {
                SharedUtils.Logger.Log("DLL Hijacking Attempted!", SharedUtils.Logger.EventLogEntryType.Error);
                MessageBox.Show("A DLL Hijacking attempt was thwarted!\n" + hijackedPath, "NetworkMiner DLL Hijacking Alert", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else {
                //Get the WinPcap adapters
                SharedUtils.Logger.Log("Loading WinPCAP Adapters", SharedUtils.Logger.EventLogEntryType.Information);
                try {
                    networkAdapters.AddRange(NetworkWrapper.WinPCapAdapter.GetAdapters());
                }
                catch (Exception ex) {
                    if (ex.InnerException != null)
                        ex = ex.InnerException;
                    SharedUtils.Logger.Log(ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    if (showWinPcapAdapterMissingError)
                        MessageBox.Show("Unable to find any WinPcap adapter, live sniffing with Raw Sockets is still possible though.\nPlease install WinPcap (www.winpcap.org) or Wireshark (www.wireshark.org) if you wish to sniff with a WindPcap adapter.\n\n" + ex.Message, "NetworkMiner", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            //get all SocketAdapters
            SharedUtils.Logger.Log("Loading Raw Sockets Adapters", SharedUtils.Logger.EventLogEntryType.Information);
            networkAdapters.AddRange(NetworkWrapper.SocketAdapter.GetAdapters());

            /*
            //get all MicroOLAP adapters
            networkAdapters.AddRange(NetworkWrapper.MicroOlapAdapter.GetAdapters());
            */
            this.networkAdaptersComboBox.DataSource = networkAdapters;

            this.framesTreeView.Nodes.Clear();

            this.treeViewsWithHostIcons = new List<TreeView>();
            treeViewsWithHostIcons.Add(this.networkHostTreeView);
            treeViewsWithHostIcons.Add(this.httpTransactionTreeView);

            foreach (TreeView treeView in treeViewsWithHostIcons) {

                treeView.ImageList = new ImageList();
                //AddImage(networkHostTreeView, "white", "white.gif");
                this.AddImage(treeView, "white", "white.jpg");//first is default
                this.AddImage(treeView, "iana", "iana.jpg");
                this.AddImage(treeView, "computer", "computer.jpg");
                this.AddImage(treeView, "multicast", "multicast.jpg");
                this.AddImage(treeView, "broadcast", "broadcast.jpg");

                this.AddImage(treeView, "windows", "windows.jpg");
                this.AddImage(treeView, "apple", "macos.jpg");
                this.AddImage(treeView, "android", "android.jpg");

                //AddImage(networkHostTreeView, "unix", "unix.gif");
                this.AddImage(treeView, "unix", "unix.jpg");
                this.AddImage(treeView, "linux", "linux.jpg");
                this.AddImage(treeView, "freebsd", "freebsd.jpg");
                this.AddImage(treeView, "netbsd", "netbsd.jpg");
                this.AddImage(treeView, "solaris", "solaris.jpg");
                this.AddImage(treeView, "siemens", "siemens.png");
                this.AddImage(treeView, "abb", "abb.png");
                this.AddImage(treeView, "ICS device", "hardhat.png");

                this.AddImage(treeView, "sent", "arrow_sent.jpg");
                this.AddImage(treeView, "received", "arrow_received.jpg");
                this.AddImage(treeView, "incoming", "arrow_incoming.jpg");
                this.AddImage(treeView, "outgoing", "arrow_outgoing.jpg");

                //this.AddImage(treeView, "nic", "network_card.jpg");
                this.AddImage(treeView, "nic", "network_socket.png");
                this.AddImage(treeView, "details", "details.gif");

                //this.AddImage(treeView, "tor", "tor.png");
                this.AddImage(treeView, "tor", "tor.gif");

                treeView.BeforeExpand += new TreeViewCancelEventHandler(extendedTreeView_BeforeExpand);
                //treeView.AfterSelect += this.TreeView_AfterSelect;
                //treeView.MouseClick += this.TreeView_MouseClick;
            }

            if (this.networkAdaptersComboBox.SelectedValue.GetType().Equals(typeof(NetworkWrapper.WinPCapAdapter)))
                this.sniffer = new NetworkWrapper.WinPCapSniffer((NetworkWrapper.WinPCapAdapter)this.networkAdaptersComboBox.SelectedValue);
            else if (this.networkAdaptersComboBox.SelectedValue.GetType().Equals(typeof(NetworkWrapper.SocketAdapter)))
                this.sniffer = new NetworkWrapper.SocketSniffer((NetworkWrapper.SocketAdapter)this.networkAdaptersComboBox.SelectedValue);
            else if (this.networkAdaptersComboBox.SelectedValue.GetType().Equals(typeof(NetworkWrapper.NullAdapter)))
                this.sniffer = null;
            else
                throw new Exception("" + this.networkAdaptersComboBox.SelectedValue.GetType().ToString());




            //this.openPcapFileDialog.Filter = "PCAP Files (*.pcap, *.cap, *.dump, *.dmp, *.eth, *.log)|*.pcap;*.cap;*.dump;*.dmp;*.eth;*.log|All Files (*.*)|*.*";
            this.openPcapFileDialog.Filter = this.GetOpenFileDialogFilter();
            this.openPcapFileDialog.FileName = "";

            this.HandleCreated += new EventHandler(LoadNextPcapFileFromCommandLineArgs);

            this.SetTextBoxText(this.messageTextBox, "[no message selected]");

            //set the control to be double buffered
            this.SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.DoubleBuffer, true);

            //parameters filter
            //this.parametersKeywordFilterControl.ListView = this.parametersListView;
            KeywordFilterControl<ListViewItem>.RegisterFilterControlCallback(this.parametersListView, this.parametersKeywordFilterControl);
            this.parametersListView.SetDoubleBuffered(true);//TODO: This should be in config
            //files filter
            //this.filesKeywordFilterControl.ListView = this.filesListView;
            KeywordFilterControl<ListViewItem>.RegisterFilterControlCallback(this.filesListView, this.filesKeywordFilterControl);
            this.filesListView.SetDoubleBuffered(true);
            //dns filter
            //this.dnsKeywordFilterControl.ListView = this.dnsListView;
            KeywordFilterControl<ListViewItem>.RegisterFilterControlCallback(this.dnsListView, this.dnsKeywordFilterControl);
            this.dnsListView.SetDoubleBuffered(true);
            //messages filter
            //this.messagesKeywordFilterControl.ListView = this.messagesListView;
            KeywordFilterControl<ListViewItem>.RegisterFilterControlCallback(this.messagesListView, this.messagesKeywordFilterControl);
            this.messagesListView.SetDoubleBuffered(true);
            //sessions filter
            //this.sessionsKeywordFilterControl.ListView = this.sessionsListView;
            KeywordFilterControl<ListViewItem>.RegisterFilterControlCallback(this.sessionsListView, this.sessionsKeywordFilterControl);
            this.sessionsListView.SetDoubleBuffered(true);
            //other lists that should be double buffered
            this.networkHostTreeView.SetDoubleBuffered(true);
            /*
            {
                this.hostsKeywordFilterControl.ClearItemsCallback = new KeywordFilterControlForTreeNodes.ClearItems(this.networkHostTreeView.Nodes.Clear);
                this.hostsKeywordFilterControl.SetItemsVisibleCallback = new KeywordFilterControlForTreeNodes.SetItemsVisible((visible) => { this.networkHostTreeView.Visible = visible; });
                this.hostsKeywordFilterControl.AddItemCallback = new KeywordFilterControlForTreeNodes.AddItem((item) => {
                    //this might get complicated...
                    this.networkHostTreeView.Nodes.Add(item);
                });
                this.hostsKeywordFilterControl.AddItemRangeCallback = new KeywordFilterControlForTreeNodes.AddItemRange(this.networkHostTreeView.Nodes.AddRange);
            }
            */

            this.httpTransactionTreeView.SetDoubleBuffered(true);
            this.imagesListView.SetDoubleBuffered(true);
            this.credentialsListView.SetDoubleBuffered(true);
            this.detectedKeywordsListView.SetDoubleBuffered(true);
            this.cleartextTextBox.SetDoubleBuffered(true);
            this.framesTreeView.SetDoubleBuffered(true);
            this.anomalyLog.SetDoubleBuffered(true);//anomalies
            this.tabControl.SetDoubleBuffered(true);

            this.pcapOverIpReceiverFactory = new PcapOverIP.PcapOverIpReceiverFactory();

            if (this.pcapOverIpReceiverFactory != null) {
                this.receivePcapOverIPToolStripMenuItem.Enabled = true;
                this.receivePcapOverIPToolStripMenuItem.Visible = true;
            }

            SharedUtils.Logger.Log("Adding Encoders", SharedUtils.Logger.EventLogEntryType.Information);
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.Default));
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.UTF8));
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.UTF7));
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.UTF32));
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.Unicode));
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.ASCII));
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.GetEncoding(850)));
            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(Encoding.GetEncoding(437)));


            //There seems to be a bug in MONO with regards to code pages it doesn't think are used: http://stackoverflow.com/a/29702302
            int[] additionalCodePages = {
                932,
                936,
                949,
                1251,
                1256,
                1252,
                28591
            };

            foreach(int codePage in additionalCodePages)
                try {
                    Encoding enc = Encoding.GetEncoding(codePage);
                    this.messageEncodingComboBox.Items.Add(new EncodingWrapper(enc));
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log(e.Message, SharedUtils.Logger.EventLogEntryType.Information);
                }

            this.messageEncodingComboBox.SelectedIndex = 0;


            this.messageAttachments = new PacketParser.PopularityList<string, List<PacketParser.FileTransfer.ReconstructedFile>>(10000);//we will be able to retrieve the 10.000 latest seen attachments

            this.GuiProperties = new GuiProperties();
            if (removeBrowsersAndVoipTab) {
                this.tabControl.TabPages.Remove(this.tabPageBrowsers);
                this._guiProperties.UseBrowsersTab = false;

                this.tabControl.TabPages.Remove(this.tabPageVoIP);
                this._guiProperties.UseVoipTab = false;
            }
            this.dictionary = new PacketParser.CleartextDictionary.WordDictionary();
            SharedUtils.Logger.Log("Loading cleartext dictionary", SharedUtils.Logger.EventLogEntryType.Information);
            this.loadCleartextDictionary("all-words.txt", this.GuiProperties.UseCleartextTab);

            this.guiUpdateTimer.Start();
            SharedUtils.Logger.Log("NetworkMinerForm constructor completed", SharedUtils.Logger.EventLogEntryType.Information);


            
            if (SharedUtils.SystemHelper.IsRunningOnMono()) {
                //inspired by KeyPass's m_tabMain.Height workaround of a Mono bug https://bugs.launchpad.net/ubuntu/+source/keepass2/+bug/891029
                //this.tabControl.Height += 5;
                //A bug in Mono causes ListViews to hide column headers when the window is resized while the ListView isn't visible
                ListView[] listViews = { this.filesListView, this.messagesListView, this.credentialsListView, this.sessionsListView, this.dnsListView, this.parametersListView, this.detectedKeywordsListView };
                foreach (ListView lv in listViews)
                    lv.VisibleChanged += (obj, args) => {
                        ListView lvToUpdate = (ListView)obj;
                        lvToUpdate.SuspendLayout();
                        lvToUpdate.SuspendLayout();
                        lvToUpdate.BeginUpdate();
                        lvToUpdate.EndUpdate();
                        lvToUpdate.ResumeLayout();
                    };
            }
            
        }

        private string GetOpenFileDialogFilter() {
            //"PCAP Files (*.pcap, *.cap, *.dump, *.dmp, *.eth, *.log)|*.pcap;*.cap;*.dump;*.dmp;*.eth;*.log|All Files (*.*)|*.*";
            StringBuilder sb = new StringBuilder();
            List<string> filters = new List<string>();

            //foreach (string extension in this.SupportedCaptureFileExtensions) {
            foreach (string extension in PcapStreamReader.PcapParserFactory.SupportedExtensions) {
                filters.Add("*." + extension);
            }
            sb.Append("Capture Files (");
            sb.Append(string.Join(", ", filters));
            sb.Append(")");
            sb.Append("|");
            sb.Append(string.Join(";", filters));
            sb.Append("|All Files (*.*)|*.*");
            return sb.ToString();
        }
        

        private void setTabPageVisibility(TabPage tab, bool setVisible) {
            if (this.tabControl.TabPages.Contains(tab) && !setVisible)
                this.tabControl.TabPages.Remove(tab);
            else if (!this.tabControl.TabPages.Contains(tab) && setVisible)
                this.tabControl.TabPages.Add(tab);
        }

        private void GuiUpdateTimer_Tick(object sender, EventArgs e) {
            if (this.IsHandleCreated) {
                if (this.frameQueue.Count > 0) {
                    List<PacketParser.Frame> fList = new List<PacketParser.Frame>();
                    while (this.frameQueue.TryDequeue(out PacketParser.Frame frame))
                        fList.Add(frame);
                    this.AddFramesToTreeView(fList);
                }
                if (this.cleartextQueue.Count > 0) {
                    StringBuilder sb = new StringBuilder();
                    while (this.cleartextQueue.TryDequeue(out string cleartext))
                        sb.Append(cleartext);

                    this.cleartextTextBox.AppendText(sb.ToString());
                }
                if (this.FileQueue.Count > 0) {
                    List<PacketParser.FileTransfer.ReconstructedFile> fList = new List<PacketParser.FileTransfer.ReconstructedFile>();
                    while (this.fileQueue.TryDequeue(out PacketParser.FileTransfer.ReconstructedFile file))
                        fList.Add(file);
                    this.AddFilesToFileList(fList);
                }
                if (this.credentialQueue.Count > 0) {
                    List<PacketParser.NetworkCredential> cList = new List<PacketParser.NetworkCredential>();
                    while (this.credentialQueue.TryDequeue(out PacketParser.NetworkCredential credential))
                        cList.Add(credential);
                    this.AddCredentialsToCredentialList(cList);
                }
                if (this.hostQueue.Count > 0) {
                    List<PacketParser.NetworkHost> hList = new List<PacketParser.NetworkHost>();
                    while (this.HostQueue.TryDequeue(out PacketParser.NetworkHost host))
                        hList.Add(host);
                    this.AddNetworkHostsToTreeView(hList);
                }
                if (this.HttpClientQueue.Count > 0) {
                    List<PacketParser.Events.HttpClientEventArgs> hList = new List<PacketParser.Events.HttpClientEventArgs>();
                    while (this.HttpClientQueue.TryDequeue(out PacketParser.Events.HttpClientEventArgs hce))
                        hList.Add(hce);
                    this.AddHttpClientToTreeView(hList);
                }
                if (this.DnsQueue.Count > 0) {
                    PacketParser.Events.DnsRecordEventArgs dre;
                    List<PacketParser.Events.DnsRecordEventArgs> rList = new List<PacketParser.Events.DnsRecordEventArgs>();
                    while (this.dnsQueue.TryDequeue(out dre)) {
                        rList.Add(dre);
                        //this.AddDnsRecordToDnsList(dre.Record, dre.DnsServer, dre.DnsClient, dre.IpPacket, dre.UdpPacket);
                    }
                    this.AddDnsRecordsToDnsList(rList);
                }

                if (this.AnomalyQueue.Count > 0) {
                    List<PacketParser.Events.AnomalyEventArgs> aList = new List<PacketParser.Events.AnomalyEventArgs>();
                    while (this.anomalyQueue.TryDequeue(out PacketParser.Events.AnomalyEventArgs ae))
                        aList.Add(ae);
                    this.ShowAnomaly(aList);
                }
                if (this.sessionQueue.Count > 0) {
                    List<PacketParser.Events.SessionEventArgs> sList = new List<PacketParser.Events.SessionEventArgs>();
                    while (this.sessionQueue.TryDequeue(out PacketParser.Events.SessionEventArgs se))
                        sList.Add(se);
                    //this.AddSessionToSessionList(se.Protocol, se.Client, se.Server, se.ClientPort, se.ServerPort, se.Tcp, se.StartFrameNumber, se.StartTimestamp);
                    this.AddSessionsToSessionList(sList);
                }
                if (this.messageQueue.Count > 0) {
                    List<PacketParser.Events.MessageEventArgs> mList = new List<PacketParser.Events.MessageEventArgs>();
                    while (this.messageQueue.TryDequeue(out PacketParser.Events.MessageEventArgs me)) {
                        mList.Add(me);
                        //this.AddMessage(me.Protocol, me.SourceHost, me.DestinationHost, me.StartFrameNumber, me.StartTimestamp, me.From, me.To, me.Subject, me.Message, me.MessageEncoding, me.Attributes);
                    }
                    this.AddMessages(mList);
                }
                if (this.parametersQueue.Count > 0) {
                    List<PacketParser.Events.ParametersEventArgs> peList = new List<PacketParser.Events.ParametersEventArgs>();
                    while (this.parametersQueue.TryDequeue(out PacketParser.Events.ParametersEventArgs pe))
                        peList.Add(pe);
                    this.AddParameters(peList);
                }
                if (this.keywordQueue.Count > 0) {
                    List<ListViewItem> keywordListViewItems = new List<ListViewItem>();
                    while (this.keywordQueue.TryDequeue(out PacketParser.Events.KeywordEventArgs ke))
                        keywordListViewItems.Add(this.createDetectedKeywordItem(ke.Frame, ke.KeywordIndex, ke.KeywordLength, ke.SourceHost, ke.DestinationHost, ke.SourcePort, ke.DestinationPort));
                    this.detectedKeywordsListView.Items.AddRange(keywordListViewItems.ToArray());
                    this.controlTextDictionary[this.tabPageKeywords] = "Keywords (" + this.detectedKeywordsListView.Items.Count + ")";
                }

                if (this.snifferBufferToolStripProgressBar.Value != this._snifferBufferToolStripProgressBarNewValue)
                    this.snifferBufferToolStripProgressBar.Value = this._snifferBufferToolStripProgressBarNewValue;

                foreach(var controlAndText in this.controlTextDictionary) {
                    if (controlAndText.Key.Text != controlAndText.Value) {
                        controlAndText.Key.Text = controlAndText.Value;
                    }
                    //this.controlTextDictionary.TryRemove(controlAndText.Key);
                }

            }
        }




        /// <summary>
        /// Funtion used to create a new PacketHandlerWrapper in case the outputDirectory has changed
        /// </summary>
        /// <param name="outputDirectory"></param>
        public void CreateNewPacketHandlerWrapper(System.IO.DirectoryInfo outputDirectory) {
            //make sure that folders exists
            try {
                System.IO.DirectoryInfo di = new System.IO.DirectoryInfo(outputDirectory.FullName + System.IO.Path.DirectorySeparatorChar + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY);
                if (!di.Exists)
                    di.Create();
                di = new System.IO.DirectoryInfo(outputDirectory.FullName + System.IO.Path.DirectorySeparatorChar + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY + System.IO.Path.DirectorySeparatorChar + "cache");
                if (!di.Exists)
                    di.Create();
                di = new System.IO.DirectoryInfo(outputDirectory.FullName + System.IO.Path.DirectorySeparatorChar + "Captures");
                if (!di.Exists)
                    di.Create();
            }
            catch (System.UnauthorizedAccessException ex) {
                SharedUtils.Logger.Log(ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                DialogResult result = MessageBox.Show("Please ensure that the user has write permissions in the AssembledFiles and Captures directories." + Environment.NewLine + Environment.NewLine + ex.Message, "Unauthorized Access");
            }

            if (this.packetHandlerWrapper != null)
                this.packetHandlerWrapper.AbortBackgroundThreads();

            //Unregister all existing events
            if (this.packetReceivedHandler != null) {
                NetworkWrapper.WinPCapSniffer.PacketReceived -= this.packetReceivedHandler;
                NetworkWrapper.SocketSniffer.PacketReceived -= this.packetReceivedHandler;
            }
            if (this.DataExporterFactory?.ResetEventHandler != null)
                this.GuiCleared -= this.DataExporterFactory.ResetEventHandler;


            if (this.PacketHandlerWrapper != null) {
                SharedUtils.Logger.Log("Creating PacketHandlerWrapper", SharedUtils.Logger.EventLogEntryType.Information);
                PacketParser.ISessionProtocolFinderFactory oldProtocolFinderFactory = this.PacketHandlerWrapper.PacketHandler.ProtocolFinderFactory;
                PacketParser.PacketHandlers.IHttpPacketHandler oldExtraHttpPacketHandler = this.PacketHandlerWrapper.PacketHandler.ExtraHttpPacketHandler;
                Dictionary<PacketParser.FileTransfer.FileStreamTypes, PacketParser.FileTransfer.IFileCarver> oldFileCarver = this.packetHandlerWrapper.PacketHandler.FileCarvers;
                this.packetHandlerWrapper = new PacketHandlerWrapper(this, outputDirectory, this.UseRelativeExtractedFilesPaths, this.preloadedFingerprints);
                //the packetHadnler needs updating
                oldProtocolFinderFactory.PacketHandler = this.packetHandlerWrapper.PacketHandler;
                //udpdate the new PacketHandler with additional properties from the old one
                this.PacketHandlerWrapper.PacketHandler.ProtocolFinderFactory = oldProtocolFinderFactory;
                this.PacketHandlerWrapper.PacketHandler.ExtraHttpPacketHandler = oldExtraHttpPacketHandler;
                this.PacketHandlerWrapper.PacketHandler.FileCarvers = oldFileCarver;
            }
            else {
                SharedUtils.Logger.Log("Replacing old PacketHandlerWrapper with a new one", SharedUtils.Logger.EventLogEntryType.Information);
                this.packetHandlerWrapper = new PacketHandlerWrapper(this, outputDirectory, this.UseRelativeExtractedFilesPaths, this.preloadedFingerprints);
            }

            //create new handler
            this.packetReceivedHandler = new SharedUtils.Pcap.PacketReceivedHandler(packetHandlerWrapper.SnifferPacketReceived);
            //this.packetReceivedHandler = new NetworkWrapper.PacketReceivedHandler(packetHandlerWrapper.SnifferPacketReceived);

            NetworkWrapper.WinPCapSniffer.PacketReceived += this.packetReceivedHandler;
            NetworkWrapper.SocketSniffer.PacketReceived += this.packetReceivedHandler;

            if (this.DataExporterFactory != null) {
                this.DataExporterFactory.RegisterHandlers(this.packetHandlerWrapper.PacketHandler);//must be done after CreateNewPacketHandlerWrapper 
                this.GuiCleared += this.DataExporterFactory.ResetEventHandler;
            }

            this.packetHandlerWrapper.StartBackgroundThreads();
        }

        void LoadNextPcapFileFromCommandLineArgs(object sender, EventArgs e) {
            string[] args = Environment.GetCommandLineArgs();
            List<string> pcapFiles = new List<string>();
            for (int i = 1; i < args.Length; i++) {
                string filePath = args[i];
                if (!filePath.StartsWith("--") || System.IO.File.Exists(filePath)) {
                    if (!this.casePanelFileListView.Items.ContainsKey(filePath)) {
                        /*
                        SharedUtils.Logger.Log("Loading " + filePath, SharedUtils.Logger.EventLogEntryType.Information);
                        BackgroundWorker fileLoader = this.LoadPcapFile(filePath);
                        if (fileLoader != null) {
                            fileLoader.RunWorkerCompleted += new RunWorkerCompletedEventHandler(this.LoadNextPcapFileFromCommandLineArgs);
                            break;
                            }
                        }
                        */
                        if (!pcapFiles.Contains(filePath))
                                pcapFiles.Add(filePath);
                    }
                }
            }
            this.LoadPcapFilesSequentially(pcapFiles);
        }

        private void AddImage(TreeView treeView, string key, string imageFileName) {
            treeView.ImageList.Images.Add(key, Image.FromFile(System.IO.Path.GetDirectoryName(System.Windows.Forms.Application.ExecutablePath) + System.IO.Path.DirectorySeparatorChar + "Images" + System.IO.Path.DirectorySeparatorChar + imageFileName));
        }

        private void AddImage(TreeView treeView, string key, Icon icon) {
            treeView.ImageList.Images.Add(key, icon);
        }



        private void AddFramesToTreeView(IEnumerable<PacketParser.Frame> frames) {
            List<TreeNode> tnList = new List<TreeNode>();
            foreach (PacketParser.Frame frame in frames) {
                TreeNode frameNode = new TreeNode(frame.ToString());
                foreach (PacketParser.Packets.AbstractPacket p in frame.PacketList/*.Values*/) {
                    TreeNode packetNode = new TreeNode(p.PacketTypeDescription + " [" + p.PacketStartIndex + "-" + p.PacketEndIndex + "]");
                    foreach (string attributeKey in p.Attributes.AllKeys)
                        packetNode.Nodes.Add(attributeKey + " = " + p.Attributes[attributeKey]);
                    frameNode.Nodes.Add(packetNode);

                    if (this._ipColorHandler != null && p is PacketParser.Packets.IIPPacket) {
                        PacketParser.Packets.IIPPacket ipPacket = (PacketParser.Packets.IIPPacket)p;
                        this._ipColorHandler.Colorize(ipPacket.SourceIPAddress, frameNode);
                        this._ipColorHandler.Colorize(ipPacket.DestinationIPAddress, frameNode);
                        this._ipColorHandler.Colorize(ipPacket.SourceIPAddress, packetNode);
                        this._ipColorHandler.Colorize(ipPacket.DestinationIPAddress, packetNode);
                    }

                }
                tnList.Add(frameNode);
            }
            this.framesTreeView.Nodes.AddRange(tnList.ToArray());
        }

        private IEnumerable<NetworkHostTreeNode> GetSiblings(System.Net.NetworkInformation.PhysicalAddress mac, System.Net.IPAddress selfIp) {
            lock (this.macToTreeNodeDictionary) {
                if (this.macToTreeNodeDictionary.Count == 0) {
                    foreach (NetworkHostTreeNode nhtv in this.networkHostTreeView.Nodes) {
                        if (nhtv.NetworkHost.MacAddress != null && nhtv.NetworkHost.IPAddress != null) {
                            if (!this.macToTreeNodeDictionary.ContainsKey(nhtv.NetworkHost.MacAddress))
                                this.macToTreeNodeDictionary.Add(nhtv.NetworkHost.MacAddress, new HashSet<NetworkHostTreeNode>());
                            this.macToTreeNodeDictionary[nhtv.NetworkHost.MacAddress].Add(nhtv);
                        }
                    }
                }
                if (this.macToTreeNodeDictionary.ContainsKey(mac)) {
                    foreach (NetworkHostTreeNode node in this.macToTreeNodeDictionary[mac])
                        if (!selfIp.Equals(node.NetworkHost.IPAddress) && !PacketParser.Utils.IpAddressUtil.IsIanaReserved(node.NetworkHost.IPAddress))
                            yield return node;
                }
                else
                    yield break;
                //if (nhtv.NetworkHost.MacAddress?.Equals(mac) == true && !selfIp.Equals(nhtv.NetworkHost.IPAddress))
                    //yield return nhtv;
            }
        }

        private void AddNetworkHostsToTreeView(IEnumerable<PacketParser.NetworkHost> hosts) {
            List<TreeNode> tnList = new List<TreeNode>();
            foreach (PacketParser.NetworkHost networkHost in hosts) {

                NetworkHostTreeNode treeNode = new NetworkHostTreeNode(networkHost, this.ipLocator, this.hostDetailsGenerator, this.GetSiblings);

                if (this._ipColorHandler != null)
                    this._ipColorHandler.Colorize(networkHost.IPAddress, treeNode);

                tnList.Add(treeNode);

            }
            this.networkHostTreeView.Nodes.AddRange(tnList.ToArray());
            this.controlTextDictionary[this.tabPageDetectedHosts] = "Hosts (" + this.packetHandlerWrapper.PacketHandler.NetworkHostList.Count + ")";
            lock (this.macToTreeNodeDictionary)
                this.macToTreeNodeDictionary.Clear();
        }

        private void AddHttpClientToTreeView(List<PacketParser.Events.HttpClientEventArgs> hList) {
            List<TreeNode> tnList = new List<TreeNode>();
            foreach (PacketParser.Events.HttpClientEventArgs hce in hList) {
                string httpClientId = hce.HttpClientId;
                PacketParser.NetworkHost networkHost = hce.Host;
                if (this.httpTransactionTreeNodeHandler != null) {
                    try {
                        TreeNode treeNode = this.httpTransactionTreeNodeHandler.GetTreeNode(httpClientId);
                        //this.httpTransactionTreeView.Nodes.Add(treeNode);
                        tnList.Add(treeNode);
                    }
                    catch (KeyNotFoundException) {
                        if (httpClientId == null) {
                            this.anomalyQueue.Enqueue(new PacketParser.Events.AnomalyEventArgs("HTTP Client ID is null", DateTime.Now));


                        }
                        else {
                            this.anomalyQueue.Enqueue(new PacketParser.Events.AnomalyEventArgs("Could not find HTTP TreeNode for " + httpClientId, DateTime.Now));
                        }
                    }
                }
            }
            this.httpTransactionTreeView.Nodes.AddRange(tnList.ToArray());
            this.controlTextDictionary[this.tabPageBrowsers] = "Browsers (" + (this.httpClientQueue.Count + this.httpTransactionTreeView.Nodes.Count) + ")";
        }

        private void OpenParentFolderInExplorer(string filePath) {
            if (filePath.Contains(System.IO.Path.DirectorySeparatorChar.ToString()))
                filePath = filePath.Substring(0, filePath.LastIndexOf(System.IO.Path.DirectorySeparatorChar));
            //System.Diagnostics.Process.Start("explorer.exe", filePath);
            SharedUtils.SystemHelper.ProcessStart(filePath);
        }

        private void AddFilesToFileList(IEnumerable<PacketParser.FileTransfer.ReconstructedFile> files) {
            List<ListViewItem> itemList = new List<ListViewItem>();
            List<Tuple<PacketParser.FileTransfer.ReconstructedFile, Bitmap>> imageFilesList = new List<Tuple<PacketParser.FileTransfer.ReconstructedFile, Bitmap>>();
            foreach (PacketParser.FileTransfer.ReconstructedFile file in files) {
                string extension = "";
                if (!string.IsNullOrEmpty(file.ExtensionFromHeader))
                    extension = file.ExtensionFromHeader;
                else if (file.Filename.Contains(".") && file.Filename.LastIndexOf('.') + 1 < file.Filename.Length)
                    extension = file.Filename.Substring(file.Filename.LastIndexOf('.') + 1);

                bool isAdvertisment = false;
                bool isTracker = false;
                string fileDetails = file.Details;
                if (this.httpTransactionTreeNodeHandler != null) {
                    isAdvertisment = this.httpTransactionTreeNodeHandler.IsAdvertisment(file.Details);
                    if (isAdvertisment)
                        fileDetails += " [Ad]";
                    isTracker = this.httpTransactionTreeNodeHandler.IsInternetTracker(file.Details);
                    if (isTracker)
                        fileDetails += " [Tracker]";
                }


                ListViewItem item = new ListViewItem(
                    new string[] {
                    file.InitialFrameNumber.ToString(),
                    file.Filename,
                    extension,
                    file.FileSizeString,
                    file.SourceHost.ToString(),
                    file.SourcePortString,
                    file.DestinationHost.ToString(),
                    file.DestinationPortString,
                    file.FileStreamType.ToString(),
                    this._guiProperties.ToCustomTimeZoneString(file.Timestamp),
                    //file.Timestamp.ToString(),
                    file.FilePath,
                    fileDetails,
                    });


                item.ToolTipText = item.Text;
                item.Tag = file.FilePath;

                if (this.httpTransactionTreeNodeHandler != null) {
                    if (isAdvertisment)
                        item.ForeColor = this._guiProperties.AdvertisementColor;
                    else if (isTracker)
                        item.ForeColor = this._guiProperties.InternetTrackerColor;
                }


                if (this._ipColorHandler != null) {
                    this._ipColorHandler.Colorize(file.SourceHost.IPAddress, item);
                    this._ipColorHandler.Colorize(file.DestinationHost.IPAddress, item);
                }



                
                itemList.Add(item);
                //this.filesKeywordFilterControl.Add(item);
                //this.controlTextDictionary[this.tabPageFiles] = "Files (" + this.filesKeywordFilterControl.UnfilteredList.Count + ")";

                try {
                    if (file.IsImage()) {
                        Bitmap bm = new Bitmap(file.FilePath);
                        imageFilesList.Add(new Tuple<PacketParser.FileTransfer.ReconstructedFile, Bitmap>(file, bm));
                        //AddImageToImageList(file, new Bitmap(file.FilePath));
                        if (file.Filename.StartsWith("favicon", StringComparison.InvariantCultureIgnoreCase) && bm.Width == bm.Height && bm.Width < 100 && bm.Height < 100 && bm.Width > 8 && bm.Height > 8 && !file.SourceHost.FaviconPerHost.ContainsKey(file.ServerHostname)) {
                            //we have a favicon between 8x8 and 100x100 pixels
                            foreach (TreeView treeView in this.treeViewsWithHostIcons) {
                                this.AddImage(treeView, file.FilePath, Icon.FromHandle(bm.GetHicon()));
                            }
                            file.SourceHost.FaviconKey = file.FilePath;
                            if (file.ServerHostname != null)
                                file.SourceHost.FaviconPerHost[file.ServerHostname] = file.FilePath;
                        }
                    }
                    else if (file.IsIcon()) {
                        Icon icon = new Icon(file.FilePath);
                        imageFilesList.Add(new Tuple<PacketParser.FileTransfer.ReconstructedFile, Bitmap>(file, icon.ToBitmap()));
                        //AddImageToImageList(file, icon.ToBitmap());
                        if (
                            file.Filename.StartsWith("favicon", StringComparison.InvariantCultureIgnoreCase) && icon.Width < 100 && icon.Height < 100 && icon.Width > 8 && icon.Height > 8 ||
                            file.Filename.EndsWith(".ico") && icon.Width == 32 && icon.Height == 32 && !file.SourceHost.FaviconPerHost.ContainsKey(file.ServerHostname)
                            ) {
                            //we have a favicon between 8x8 and 100x100 pixels
                            //TODO add icon as default icon for the host in the hosts tab
                            foreach (TreeView treeView in this.treeViewsWithHostIcons) {
                                this.AddImage(treeView, file.FilePath, icon);
                            }
                            file.SourceHost.FaviconKey = file.FilePath;
                            if (file.ServerHostname != null)
                                file.SourceHost.FaviconPerHost[file.ServerHostname] = file.FilePath;
                        }
                    }
                }
                catch (Exception e) {
                    this.anomalyQueue.Enqueue(new PacketParser.Events.AnomalyEventArgs("Error: Exception when loading image \"" + file.Filename + "\". " + e.Message, DateTime.Now));
                    //this.ShowAnomaly("Error: Exception when loading image \"" + file.Filename + "\". " + e.Message, DateTime.Now);
                }
            }
            this.filesKeywordFilterControl.AddRange(itemList);
            this.controlTextDictionary[this.tabPageFiles] = "Files (" + this.filesKeywordFilterControl.UnfilteredList.Count + ")";
            if(imageFilesList.Count > 0)
                this.AddImagesToImageList(imageFilesList);

        }

        private void AddParameters(IEnumerable<PacketParser.Events.ParametersEventArgs> parameters) {
            List<ListViewItem> newItems = new List<ListViewItem>();

            foreach (PacketParser.Events.ParametersEventArgs p in parameters) {
                //this.AddParameters(pe.FrameNumber, pe.SourceHost, pe.DestinationHost, pe.SourcePort, pe.DestinationPort, pe.Parameters, pe.Timestamp, pe.Details);
                
                foreach (string parameterName in p.Parameters.AllKeys) {

                    ListViewItem item = new ListViewItem(
                        new string[] {
                        parameterName,
                        p.Parameters[parameterName],
                        p.FrameNumber.ToString(),
                        p.SourceHost.ToString(),
                        p.SourcePort,
                        p.DestinationHost.ToString(),
                        p.DestinationPort,
                        this._guiProperties.ToCustomTimeZoneString(p.Timestamp),//.ToString(),
                        p.Details
                        });
                    item.ToolTipText = parameterName + " = " + p.Parameters[parameterName];

                    //add a tag
                    System.Collections.Generic.KeyValuePair<string, string> nameValueTag = new KeyValuePair<string, string>(parameterName, p.Parameters[parameterName]);
                    item.Tag = nameValueTag;

                    if (this._ipColorHandler != null) {
                        this._ipColorHandler.Colorize(p.SourceHost.IPAddress, item);
                        this._ipColorHandler.Colorize(p.DestinationHost.IPAddress, item);
                    }
                    newItems.Add(item);
                }

                
            }
            this.parametersKeywordFilterControl.AddRange(newItems);//adds the parameter if it passes the filter

            this.controlTextDictionary[this.tabPageParameters] = "Parameters (" + this.parametersKeywordFilterControl.UnfilteredList.Count + ")";
            //this.SetControlText(this.tabPageParameters, "Parameters (" + this.parametersKeywordFilterControl.UnfilteredList.Count + ")");

        }

        private void AddSessionsToSessionList(List<PacketParser.Events.SessionEventArgs> sList){
            List<ListViewItem> newItems = new List<ListViewItem>();
            foreach (PacketParser.Events.SessionEventArgs se in sList) {
                /*
                PacketParser.ApplicationLayerProtocol protocol;
                PacketParser.NetworkHost client;
                PacketParser.NetworkHost server;
                ushort clientPort;
                ushort serverPort;
                bool tcp;
                long startFrameNumber;
                DateTime startTimestamp;
                */
                string protocolString = "";
                if (se.Protocol != PacketParser.ApplicationLayerProtocol.Unknown)
                    protocolString = se.Protocol.ToString();

                ListViewItem item = new ListViewItem(
                    new string[] {
                    se.StartFrameNumber.ToString(),
                    se.Client.ToString(),
                    se.ClientPort.ToString(),//add "TCP" ?
                    se.Server.ToString(),
                    se.ServerPort.ToString(),
                    protocolString,
                    this._guiProperties.ToCustomTimeZoneString(se.StartTimestamp)//.ToString()
                    });

                //item.Tag = session;//this might occupy a lot of memory....
                //no tooltip...

                if (this._ipColorHandler != null) {
                    this._ipColorHandler.Colorize(se.Client.IPAddress, item);
                    this._ipColorHandler.Colorize(se.Server.IPAddress, item);
                }
                newItems.Add(item);
            }
            this.sessionsKeywordFilterControl.AddRange(newItems);
            this.controlTextDictionary[this.tabPageSessions] = "Sessions (" + this.sessionsKeywordFilterControl.UnfilteredList.Count + ")";
        }


        private void AddMessages(List<PacketParser.Events.MessageEventArgs> mList) {
            List<ListViewItem> newItems = new List<ListViewItem>();
            foreach (PacketParser.Events.MessageEventArgs me in mList) {
                ListViewItem item = new ListViewItem(
                    new string[] {
                    me.StartFrameNumber.ToString(),
                    me.SourceHost.ToString(),
                    me.DestinationHost.ToString(),
                    me.From,
                    me.To,
                    me.Subject,
                    me.Protocol.ToString(),
                    this._guiProperties.ToCustomTimeZoneString(me.StartTimestamp),//.ToString()
                    me.Size.ToString()
                    });


                byte[] messageBytes;
                if (string.IsNullOrEmpty(me.Message))
                    messageBytes = new byte[0];
                else
                    me.MessageEncoding.GetBytes(me.Message);
                //set the message and attributes as tag for retrieval from the GUI when the message is selected
                Tuple<System.Collections.Specialized.NameValueCollection, byte[], Encoding> tuple = new Tuple<System.Collections.Specialized.NameValueCollection, byte[], Encoding>(me.Attributes, me.MessageEncoding.GetBytes(me.Message), me.MessageEncoding);
                int messageMaxLength = 10000;
                if (tuple.Item2?.Length > messageMaxLength) {
                    byte[] newMessage = new byte[messageMaxLength];
                    Array.Copy(tuple.Item2, newMessage, messageMaxLength);
                    tuple = new Tuple<System.Collections.Specialized.NameValueCollection, byte[], Encoding>(tuple.Item1, newMessage, me.MessageEncoding);
                }
                item.Tag = tuple;
                newItems.Add(item);


                if (this._ipColorHandler != null) {
                    this._ipColorHandler.Colorize(me.SourceHost.IPAddress, item);
                    this._ipColorHandler.Colorize(me.DestinationHost.IPAddress, item);
                }

            }
            this.messagesKeywordFilterControl.AddRange(newItems);
            this.controlTextDictionary[this.tabPageMessages] = "Messages (" + this.messagesKeywordFilterControl.UnfilteredList.Count + ")";

        }

        private void AddMessageAttachment(string messageId, PacketParser.FileTransfer.ReconstructedFile file) {
            //no invoke required here...
            lock (this.messageAttachments) {
                if (this.messageAttachments.ContainsKey(messageId)) {
                    this.messageAttachments[messageId].Add(file);
                }
                else {
                    List<PacketParser.FileTransfer.ReconstructedFile> attachments = new List<PacketParser.FileTransfer.ReconstructedFile>();
                    attachments.Add(file);
                    this.messageAttachments.Add(messageId, attachments);
                }
            }
        }

        private void AddCredentialsToCredentialList(IEnumerable<PacketParser.NetworkCredential> credentials) {
            this.AddCredentialsToCredentialList(credentials, true);
        }

        private void AddCredentialsToCredentialList(IEnumerable<PacketParser.NetworkCredential> credentials, bool updateTabCount) {
            List<ListViewItem> newItems = new List<ListViewItem>();
            Regex cookieRegex = new Regex("^HTTP(/2)? Cookie$");
            foreach (PacketParser.NetworkCredential credential in credentials) {
                if (
                    //(this.showCookiesCheckBox.Checked || !credential.ProtocolString.ToLower().Contains("cookie")) &&
                    //(this.showCookiesCheckBox.Checked || !credential.ProtocolString.Equals("HTTP Cookie", StringComparison.InvariantCulture)) &&
                    (this.showCookiesCheckBox.Checked || !cookieRegex.IsMatch(credential.ProtocolString)) &&
                    (this.showNtlmSspCheckBox.Checked || !credential.ProtocolString.ToUpper().Contains("NTLMSSP"))
                    ) {
                    string validCredential = "Unknown";
                    if (credential.IsProvenValid)
                        validCredential = "Yes";

                    string displayedPassword = "";
                    if (credential.Password == null)
                        displayedPassword = "";
                    else if (this.maskPasswordsCheckBox.Checked)
                        displayedPassword = new String('*', credential.Password.Length);
                    else
                        displayedPassword = credential.Password;

                    string serverString = credential.Server.ToString();
                    if (credential.Domain?.Length > 0)
                        serverString = credential.Server.IPAddress.ToString() + " [" + credential.Domain + "]";

                    ListViewItem item = new ListViewItem(
                        new string[] {
                    credential.Client.ToString(),
                    serverString,
                    credential.ProtocolString,
                    credential.Username,
                    //ByteConverter.ToMd5HashString(credential.Password),//credential.Password
                    displayedPassword,
                    validCredential,
                    this._guiProperties.ToCustomTimeZoneString(credential.LoginTimestamp)//.ToString()
                        });

                    item.Tag = credential;
                    item.ToolTipText = item.Text;





                    if (this._ipColorHandler != null) {
                        if (credential.Client != null)
                            this._ipColorHandler.Colorize(credential.Client.IPAddress, item);
                        if (credential.Server != null)
                            this._ipColorHandler.Colorize(credential.Server.IPAddress, item);
                    }
                    //this.credentialsListView.Items.Add(item);
                    newItems.Add(item);
                }
            }
            this.credentialsListView.Items.AddRange(newItems.ToArray());
            if (updateTabCount)
                this.controlTextDictionary[this.tabPageCredentials] = "Credentials (" + credentialsListView.Items.Count + ")";

        }

        private void AddImagesToImageList(IEnumerable<Tuple<PacketParser.FileTransfer.ReconstructedFile, Bitmap>> imageTuples) {
            List<ListViewItem> newItems = new List<ListViewItem>();
            foreach (var t in imageTuples) {
                PacketParser.FileTransfer.ReconstructedFile file = t.Item1;
                Bitmap bitmapImage = t.Item2;
                this.imageList.Images.Add(new Bitmap(bitmapImage));//I do the new in order to release the file handle for the original file
                ListViewItem item = new ListViewItem(file.Filename + "\n" + bitmapImage.Width + "x" + bitmapImage.Height + ", " + file.FileSizeString, imageList.Images.Count - 1);
                newItems.Add(item);
                //this.imagesListView.Items.Add(file.Filename + "\n" + bitmapImage.Width + "x" + bitmapImage.Height + ", " + file.FileSizeString, imageList.Images.Count - 1);
                item.Tag = file;
                item.ToolTipText = "Source: " + file.SourceHost + "\nDestination: " + file.DestinationHost + "\nReconstructed file path: " + file.FilePath;

                if (this._ipColorHandler != null) {
                    this._ipColorHandler.Colorize(file.SourceHost.IPAddress, item);
                    this._ipColorHandler.Colorize(file.DestinationHost.IPAddress, item);
                }

            }
            this.imagesListView.Items.AddRange(newItems.ToArray());
            this.controlTextDictionary[this.tabPageImages] = "Images (" + this.imageList.Images.Count + ")";
        }


        private void AddDnsRecordsToDnsList(IEnumerable<PacketParser.Events.DnsRecordEventArgs> records) {
            List<ListViewItem> newItems = new List<ListViewItem>();

            foreach (PacketParser.Events.DnsRecordEventArgs r in records) {

                string queriedName = null;
                string answeredName = null;

                if (r.Record.DNS != null)
                    queriedName = r.Record.DNS;
                else
                    continue;

                if(r.Record.Type == (ushort)PacketParser.Packets.DnsPacket.RRTypes.TXT)
                    answeredName = r.Record.TXT;
                else if (r.Record.IP != null)
                    answeredName = r.Record.IP.ToString();
                else if (r.Record.PrimaryName != null)
                    answeredName = r.Record.PrimaryName;
                else if (r.Record is PacketParser.Packets.DnsPacket.ResponseWithErrorCode)
                    answeredName = (r.Record as PacketParser.Packets.DnsPacket.ResponseWithErrorCode).GetResultCodeString();
                else
                    continue;

                string recordTypeString = "0x" + r.Record.Type.ToString("X4");
                Type rrType = typeof(PacketParser.Packets.DnsPacket.RRTypes);
                if (Enum.IsDefined(rrType, r.Record.Type))
                    recordTypeString += " (" + Enum.GetName(rrType, r.Record.Type) + ")";
                /*
                if (r.Record.Type == (ushort)PacketParser.Packets.DnsPacket.RRTypes.CNAME)
                    recordTypeString += " (CNAME)";
                else if (r.Record.Type == (ushort)PacketParser.Packets.DnsPacket.RRTypes.DomainNamePointer)
                    recordTypeString += " (Domain Name Pointer)";
                else if (r.Record.Type == (ushort)PacketParser.Packets.DnsPacket.RRTypes.HostAddress)
                    recordTypeString += " (Host Address)";
                else if (r.Record.Type == (ushort)PacketParser.Packets.DnsPacket.RRTypes.NB)
                    recordTypeString += " (NB)";
                // NBSTAT records are obsolete. Replaced with SRV (rfc2782)
                //else if (r.Record.Type == (ushort)PacketParser.Packets.DnsPacket.RRTypes.NBSTAT)
                //    recordTypeString += " (NBSTAT)";
                else if (r.Record.Type == (ushort)PacketParser.Packets.DnsPacket.RRTypes.TXT)
                    recordTypeString += " (TXT)";
                    */

                string serverUdpPort = "unknown";
                string clientUdpPort = "unknown";
                if (r.TransportLayerPacket != null) {
                    serverUdpPort = r.TransportLayerPacket.SourcePort.ToString();
                    clientUdpPort = r.TransportLayerPacket.DestinationPort.ToString();
                }

                string alexaTop1m;
                if (this.domainNameFilter == null)
                    alexaTop1m = "N/A (Pro version only)";
                else if (this.domainNameFilter.ContainsDomain(queriedName, out alexaTop1m) || (r.Record.PrimaryName != null && this.domainNameFilter.ContainsDomain(answeredName, out alexaTop1m)))
                    alexaTop1m = "Yes (" + alexaTop1m + ")";
                else
                    alexaTop1m = "No";

                string ipTTL;
                if (r.IpPacket is PacketParser.Packets.IPv4Packet ipv4)
                    ipTTL = ipv4.TimeToLive.ToString();
                else
                    ipTTL = "N/A";

                ListViewItem item = new ListViewItem(
                    new string[] {
                    r.Record.ParentPacket.ParentFrame.FrameNumber.ToString(),
                    this._guiProperties.ToCustomTimeZoneString(r.Record.ParentPacket.ParentFrame.Timestamp),//.ToString(),
                    r.DnsClient.ToString(),
                    clientUdpPort,
                    r.DnsServer.ToString(),
                    serverUdpPort,
                    ipTTL,
                    r.Record.TimeToLive.ToString(),
                    "0x"+r.Record.ParentPacket.TransactionId.ToString("X4"),
                    recordTypeString,
                    queriedName,
                    answeredName,
                    alexaTop1m,
                    });
                newItems.Add(item);

                item.ToolTipText = item.Text;

                if (this._ipColorHandler != null) {
                    if (r.Record != null && r.Record.IP != null)
                        this._ipColorHandler.Colorize(r.Record.IP, item);
                    if (r.IpPacket != null) {
                        this._ipColorHandler.Colorize(r.IpPacket.SourceIPAddress, item);
                        this._ipColorHandler.Colorize(r.IpPacket.DestinationIPAddress, item);
                    }
                    if (r.DnsClient != null)
                        this._ipColorHandler.Colorize(r.DnsClient.IPAddress, item);
                    if (r.DnsServer != null)
                        this._ipColorHandler.Colorize(r.DnsServer.IPAddress, item);
                }
                
            }
            this.dnsKeywordFilterControl.AddRange(newItems);//adds the parameter if it passes the filter
            this.controlTextDictionary[this.tabPageDns] = "DNS (" + this.dnsKeywordFilterControl.UnfilteredList.Count + ")";
        }

        private void TreeView_AfterSelect(object sender, TreeViewEventArgs e) {
            if (e.Node is NetworkHostTreeNode.TreeNodeLink link) {
                this.BeginInvoke((MethodInvoker) delegate { link.TreeView.SelectedNode = link.LinkedTreeNode; });
                //link.TreeView.SelectedNode = link.LinkedTreeNode;//sometimes selects the wrong node?!
            }
        }

        //Generic function to expand child nodes in the networkHostTreeView
        void extendedTreeView_BeforeExpand(object sender, TreeViewCancelEventArgs e) {
            if (e.Node is ToolInterfaces.IBeforeExpand expandable) {
                expandable.BeforeExpand();
            }
        }


        //see: ms-help://MS.VSCC.v80/MS.MSDN.v80/MS.VisualStudio.v80.en/dv_fxmclictl/html/138f38b6-1099-4fd5-910c-390b41cbad35.htm
        //or: http://www.osix.net/modules/article/?id=832
        internal void ShowReceivedFrame(PacketParser.Frame frame) {

            this.controlTextDictionary[this.tabPageReceivedFrames] = "Frames (" + frame.FrameNumber + ")";

            foreach (PacketParser.Frame.Error error in frame.Errors) {
                this.anomalyQueue.Enqueue(new PacketParser.Events.AnomalyEventArgs(error.ToString() + " (frame nr: " + frame.FrameNumber + ")", frame.Timestamp));
            }


            if (this.framesTreeView.Nodes.Count + this.frameQueue.Count < this._guiProperties.MaxDisplayedFrames || this._guiProperties.MaxDisplayedFrames < 0) {

                this.frameQueue.Enqueue(frame);
            }
        }

        internal void ShowCleartextWords(IEnumerable<string> words, int wordCharCount, int totalByteCount) {
            if (wordCharCount * 16 > totalByteCount) {//at least 1/16 of the data shall be clear text, otherwise it is probable to be false positives
                StringBuilder sb = new StringBuilder();
                foreach (string word in words) {
                    sb.Append(word);
                    sb.Append(" ");
                }

                this.cleartextTextBox.ForeColor = System.Drawing.Color.Red;

                this.cleartextQueue.Enqueue(sb.ToString());
            }
        }
        
        private void ShowAnomaly(List<PacketParser.Events.AnomalyEventArgs> anomalyList) {
            StringBuilder sb = new StringBuilder();
            foreach (var ae in anomalyList) {
                string errorText = ae.Message;
                DateTime errorTimestamp = ae.Timestamp;
#if DEBUG
                if (this.InvokeRequired)//we should always arrive here in a thread safe manner
                    System.Diagnostics.Debugger.Break();
#endif
                SharedUtils.Logger.Log(errorText, SharedUtils.Logger.EventLogEntryType.Information);
                sb.AppendLine("[" + this._guiProperties.ToCustomTimeZoneString(errorTimestamp) + "] Error : " + errorText);
            }
            //this.anomalyLog.AppendText("\r\n[" + this.guiProperties.ToCustomTimeZoneString(errorTimestamp) + "] Error : " + errorText);
            this.anomalyLog.AppendText(sb.ToString());

        }

        internal void ShowMessageAttachment(string messageId, PacketParser.FileTransfer.ReconstructedFile file) {
            if (this._guiProperties.UseMessagesTab) {
                this.AddMessageAttachment(messageId, file);
            }
        }

        /*
        internal void Assembler_FileReconstructed(string extendedFileId, PacketParser.FileTransfer.ReconstructedFile file) {
            throw new NotImplementedException();
        }
        */

        /// <summary>
        /// Returns the selected index in the Dropdown ComboBox for Cleartext Search
        /// </summary>
        /// <returns>0 [Full content search], 1 [Raw packet search], 2 [No search]</returns>
        internal int GetCleartextSearchModeIndex() {

            //http://www.csharp411.com/property-delegates-with-anonymous-methods/
            return (int)this.Invoke((GetIntValueCallback)delegate () { return this.cleartextSearchModeComboBox.SelectedIndex; });

        }

        internal int GetHostSortOrderIndex() {

            //http://www.csharp411.com/property-delegates-with-anonymous-methods/
            return (int)this.Invoke((GetIntValueCallback)delegate () { return this.hostSortOrderComboBox.SelectedIndex; });

        }




        //http://www.codeproject.com/csharp/begininvoke.asp?df=100&forumid=178776&exp=0&select=1519433
        [System.Obsolete("This function is obsolete. Use this.controlTextDictionary instead.", true)]
        private void SetControlText(Control c, string text, bool forcedUpdate = false) {
            this.controlTextDictionary[c] = text;

        }


        private void CopyCredentialUsernameToClipboard_Click(object sender, EventArgs e) {
            if (credentialsListView.SelectedItems.Count > 0) {
                PacketParser.NetworkCredential c = (PacketParser.NetworkCredential)credentialsListView.SelectedItems[0].Tag;
                Clipboard.SetDataObject(c.Username, true);
            }
        }
        private void CopyCredentialPasswordToClipboard_Click(object sender, EventArgs e) {
            if (credentialsListView.SelectedItems.Count > 0) {
                PacketParser.NetworkCredential c = (PacketParser.NetworkCredential)credentialsListView.SelectedItems[0].Tag;
                Clipboard.SetDataObject(c.Password, true);
            }
        }
        private void OpenImage_Click(object sender, EventArgs e) {
            if (imagesListView.SelectedItems.Count > 0) {
                PacketParser.FileTransfer.ReconstructedFile file = (PacketParser.FileTransfer.ReconstructedFile)imagesListView.SelectedItems[0].Tag;
                try {
                    //System.Diagnostics.Process.Start(file.FilePath);
                    SharedUtils.SystemHelper.ProcessStart(file.FilePath);
                }
                catch (Exception ex) {
                    MessageBox.Show(ex.Message);
                }
            }
        }
        private void ImageZoomIn(object sender, EventArgs e) {
            this.imageZoom(1.5);
        }
        private void ImageZoomOut(object sender, EventArgs e) {
            this.imageZoom(1.0 / 1.5);
        }

        private void imageZoom(double zoomFactor) {
            List<ListViewItem> itemList = new List<ListViewItem>();
            foreach (ListViewItem item in this.imagesListView.Items) {
                itemList.Add(item);
            }
            Size imageSize = new Size(Math.Min((int)(this.imagesListView.LargeImageList.ImageSize.Width * zoomFactor), 256), Math.Min((int)(this.imagesListView.LargeImageList.ImageSize.Height * zoomFactor), 256));
            this.imagesListView.LargeImageList.ImageSize = imageSize;
            //this.imagesListView.LargeImageList.ImageSize.Width = this.imagesListView.LargeImageList.ImageSize.Width * 2;
            this.imageList.Images.Clear();
            this.imagesListView.Visible = false;
            this.imagesListView.Items.Clear();
            //this.imagesListView.Font = new Font(this.imagesListView.Font.FontFamily, (float)(this.imagesListView.Font.Size * Math.Sqrt(zoomFactor)));

            for (int i = 0; i < itemList.Count; i++) {
                PacketParser.FileTransfer.ReconstructedFile file = itemList[i].Tag as PacketParser.FileTransfer.ReconstructedFile;
                this.imageList.Images.Add(new Bitmap(file.FilePath));
                ListViewItem lvItem = this.imagesListView.Items.Add(itemList[i].Text, i);
                lvItem.Tag = file;
                lvItem.ToolTipText = "Source: " + file.SourceHost + "\nDestination: " + file.DestinationHost + "\nReconstructed file path: " + file.FilePath;
            }
            
            this.imagesListView.Visible = true;
            this.imagesListView.Select();
        }

        private void autoResizeFileColumns_Click(object sender, EventArgs e) {
            this.resizeListViewColumns(this.filesListView);
        }
        private void autoResizeCredentialsColumns_Click(object sender, EventArgs e) {
            this.resizeListViewColumns(this.credentialsListView);
        }
        private void autoResizeParameterColumns_Click(object sender, EventArgs e) {
            this.resizeListViewColumns(this.parametersListView);
        }

        private void resizeListViewColumns(ListView lv) {
            SharedUtils.Logger.Log("Resizing ListView " + lv.Name, SharedUtils.Logger.EventLogEntryType.Information);
            lv.SuspendLayout();
            lv.BeginUpdate();

            foreach (ColumnHeader column in lv.Columns) {
                column.Width = -2;
            }
            
            lv.EndUpdate();
            lv.BeginUpdate();

            if (this.GuiProperties.ColumnAutoResizeMaxWidth > 0) {


                //this one fails to make the first column smaller for some reason
                if (lv.Items.Count > 0 && lv.Items[0] != null && lv.Items[0].Bounds.Width > this.GuiProperties.ColumnAutoResizeMaxWidth) {
                    ListViewItem item = lv.Items[0];
                    for (int i = 1; i < item.SubItems.Count; i++)
                        if (item.SubItems[i] != null) {
                            ListViewItem.ListViewSubItem subItem = item.SubItems[i];
                            if (subItem.Bounds.Width > this.GuiProperties.ColumnAutoResizeMaxWidth)
                                lv.Columns[i].Width = this.GuiProperties.ColumnAutoResizeMaxWidth;
                        }
                }

                //this one fixes the first column, and probably the others as well, but doesn't work until after the SubItem iteration above
                for (int i = 0; i < lv.Columns.Count; i++) {
                    if (lv.Columns[i].Width > this.GuiProperties.ColumnAutoResizeMaxWidth)
                        lv.Columns[i].Width = this.GuiProperties.ColumnAutoResizeMaxWidth;
                    
                    //to fix bugs in Mono GUI code, much like KeyPass's MonoWorkarounds.IsRequired(686017)
                    else if (SharedUtils.SystemHelper.IsRunningOnMono() && lv.Columns[i].Width < 33) {
                        lv.Columns[i].Width = 33;
                    }
                    
                }
            }
            lv.EndUpdate();
            lv.ResumeLayout();
        }

        //see: ms-help://MS.VSCC.v80/MS.MSDN.v80/MS.NETDEVFX.v20.en/CPref17/html/C_System_Windows_Forms_ToolStripMenuItem_ctor_2_8a3c7c15.htm
        private void OpenFile_Click(object sender, EventArgs e) {
            OpenFile_Click(this.filesListView);

        }
        private void OpenAttachment_Click(object sender, EventArgs e) {
            OpenFile_Click(this.messageAttachmentListView);
        }
        private static void OpenFile_Click(ListView listView) {
            //http://msdn2.microsoft.com/en-us/library/system.diagnostics.process.start(VS.71).aspx
            if (listView.SelectedItems.Count > 0) {
                string filePath = listView.SelectedItems[0].Tag.ToString();//.Text;
                string fileName = System.IO.Path.GetFileName(filePath);
                
                if(!SharedUtils.SystemHelper.IsRunningOnMono() && PacketParser.FileTransfer.FileStreamAssembler.ExecutableExtensions.Contains(fileName.Split('.').Last()?.ToLower())) {
                    var yesOrNo = MessageBox.Show(fileName + Environment.NewLine + Environment.NewLine + "Are you sure you want to run this executable file?", "Warning - Executable File!", MessageBoxButtons.YesNo);
                    if (yesOrNo != DialogResult.Yes)
                        return;
                }
                try {
                    SharedUtils.Logger.Log("Opening file " + filePath, SharedUtils.Logger.EventLogEntryType.Information);
                    //System.Diagnostics.Process.Start(filePath);
                    SharedUtils.SystemHelper.ProcessStart(filePath);
                }
                catch (Exception ex) {
                    
                    SharedUtils.Logger.Log(ex.GetType().ToString() + " : " + ex.Message + " " + filePath, SharedUtils.Logger.EventLogEntryType.Error);
                    MessageBox.Show(filePath, ex.GetType().ToString() + " : " + ex.Message);
                }
            }
        }
        //see: ms-help://MS.VSCC.v80/MS.MSDN.v80/MS.NETDEVFX.v20.en/CPref17/html/C_System_Windows_Forms_ToolStripMenuItem_ctor_2_8a3c7c15.htm
        private void OpenFileFolder_Click(object sender, EventArgs e) {
            OpenFolder_Click(this.filesListView);
        }
        private void OpenAttachmentFolder_Click(object sender, EventArgs e) {
            OpenFolder_Click(this.messageAttachmentListView);
        }
        private static void OpenFolder_Click(ListView listView) {
            if (listView.SelectedItems.Count > 0) {
                string filePath = listView.SelectedItems[0].Tag.ToString();//.Text;
                string folderPath = filePath;
                if (filePath.Contains(System.IO.Path.DirectorySeparatorChar.ToString()))
                    folderPath = filePath.Substring(0, filePath.LastIndexOf(System.IO.Path.DirectorySeparatorChar) + 1);

                SharedUtils.Logger.Log("Opening folder " + folderPath, SharedUtils.Logger.EventLogEntryType.Information);
                try {
                    //System.Diagnostics.Process.Start(folderPath);
                    SharedUtils.SystemHelper.ProcessStart(folderPath);
                }
                catch (Exception ex) {
                    SharedUtils.Logger.Log(ex.GetType().ToString() + " : " + ex.Message + " " + folderPath, SharedUtils.Logger.EventLogEntryType.Error);
                    MessageBox.Show(folderPath, ex.GetType().ToString() + " : " + ex.Message);
                }
            }
        }

        private void startButton_Click(object sender, EventArgs e) {
            networkAdaptersComboBox.Enabled = false;
            startButton.Enabled = false;
            startCapturingToolStripMenuItem.Enabled = false;
            //System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath)
            //Path.GetDirectoryName(applicationExecutablePath)+"\\";
            if (packetHandlerWrapper.PcapWriter != null && packetHandlerWrapper.PcapWriter.IsOpen)
                packetHandlerWrapper.PcapWriter.Close();
            string filename = Tools.GenerateCaptureFileName(DateTime.Now);
            //string filename="NM_"+DateTime.Now.ToString("s", System.Globalization.DateTimeFormatInfo.InvariantInfo).Replace(':','-')+".pcap";

            string fileFullPath = this.OutputDirectory.FullName + "Captures" + System.IO.Path.DirectorySeparatorChar + filename;
            //string fileFullPath = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath)) + System.IO.Path.DirectorySeparatorChar + "Captures" + System.IO.Path.DirectorySeparatorChar + filename;

            //make sure to get the right datalink type
            PcapFrame.DataLinkTypeEnum dataLinkType;
            if (sniffer.BasePacketType == PacketReceivedEventArgs.PacketTypes.Ethernet2Packet)
                dataLinkType = PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET;
            else if (sniffer.BasePacketType == PacketReceivedEventArgs.PacketTypes.IEEE_802_11Packet)
                dataLinkType = PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11;
            else if (sniffer.BasePacketType == PacketReceivedEventArgs.PacketTypes.IEEE_802_11RadiotapPacket)
                dataLinkType = PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP;
            else if (sniffer.BasePacketType == PacketReceivedEventArgs.PacketTypes.IPv4Packet)
                dataLinkType = PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP;
            else
                dataLinkType = PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET;

            this.packetHandlerWrapper.PcapWriter = new PcapFileWriter(fileFullPath, dataLinkType);

            SharedUtils.Logger.Log("Starting packet capture on " + sniffer.BasePacketType + " interface", SharedUtils.Logger.EventLogEntryType.Information);
            //now let's start sniffing!
            this.sniffer.StartSniffing();

            this.AddPcapFileToCasePanel(fileFullPath, filename);


        }

        public void AddPcapFileToCasePanel(string fileFullPath, string filename) {
            this.AddPcapFileToCasePanel(new CaseFile(fileFullPath), false);
        }

        public void AddPcapFileToCasePanel(CaseFile caseFile, bool computeMd5) {
            if (this.InvokeRequired)
                this.Invoke((MethodInvoker)delegate () { AddPcapFileToCasePanel(caseFile, computeMd5); });
            else {
                ListViewItem pcapFileListViewItem = this.casePanelFileListView.Items.Add(caseFile.FilePathAndName, caseFile.Filename, null);
                if (computeMd5) {
                    caseFile.Md5 = SharedUtils.Md5SingletonHelper.Instance.GetMd5Sum(caseFile.FilePathAndName);
                    pcapFileListViewItem.SubItems.Add(caseFile.Md5);
                }
                pcapFileListViewItem.ToolTipText = caseFile.FilePathAndName;
                pcapFileListViewItem.Tag = caseFile;//stores metadata and more
            }
        }

        private void stopButton_Click(object sender, EventArgs e) {
            if (sniffer != null) {
                sniffer.StopSniffing();
                this.UpdateGuiControlsAfterParsingCompleteEventHandler(sender, e);
                //detectedHostsTreeRebuildButton_Click(sender, e);//in order to rebuild the detected hosts list
            }
            networkAdaptersComboBox.Enabled = true;
            if (!this.networkAdaptersComboBox.SelectedValue.GetType().Equals(typeof(NetworkWrapper.NullAdapter))) {
                startButton.Enabled = true;
                startCapturingToolStripMenuItem.Enabled = true;
            }
            if (packetHandlerWrapper.PcapWriter != null && packetHandlerWrapper.PcapWriter.IsOpen)
                packetHandlerWrapper.PcapWriter.Close();
            if (packetHandlerWrapper.PcapWriter != null && packetHandlerWrapper.PcapWriter.Filename != null && casePanelFileListView.Items.ContainsKey(packetHandlerWrapper.PcapWriter.Filename))
                casePanelFileListView.Items[packetHandlerWrapper.PcapWriter.Filename].SubItems.Add(SharedUtils.Md5SingletonHelper.Instance.GetMd5Sum(packetHandlerWrapper.PcapWriter.Filename));
        }

        private void button3_Click(object sender, EventArgs e) {
            anomalyLog.Clear();
        }

        private void networkAdaptersComboBox_SelectedIndexChanged(object sender, EventArgs e) {
            if (this.networkAdaptersComboBox.SelectedValue.GetType().Equals(typeof(NetworkWrapper.WinPCapAdapter))) {
                this.sniffer = new NetworkWrapper.WinPCapSniffer((NetworkWrapper.WinPCapAdapter)this.networkAdaptersComboBox.SelectedValue);
                this.startButton.Enabled = true;
                this.startCapturingToolStripMenuItem.Enabled = true;
            }
            else if (this.networkAdaptersComboBox.SelectedValue.GetType().Equals(typeof(NetworkWrapper.SocketAdapter))) {
                try {
                    this.sniffer = new NetworkWrapper.SocketSniffer((NetworkWrapper.SocketAdapter)this.networkAdaptersComboBox.SelectedValue);
                    this.startButton.Enabled = true;
                    this.startCapturingToolStripMenuItem.Enabled = true;
                }
                catch (System.Net.Sockets.SocketException ex) {
                    SharedUtils.Logger.Log("SocketException when creating SocketSniffer: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    MessageBox.Show(@"To capture traffic with a raw socket, please follow these steps:
1. Create an Inboud Rule in the Windows firewall for NetworkMiner.
2. Start NetworkMiner with administrator rights.");
                    //MessageBox.Show("Ensure that you have administrator rights (required in order to use Socket connections)\n\n"+ex.Message, "NetworkMiner", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    this.networkAdaptersComboBox.SelectedIndex = 0;
                    this.startButton.Enabled = false;
                    this.startCapturingToolStripMenuItem.Enabled = false;
                }
                catch (System.Exception ex) {
                    MessageBox.Show(ex.Message, "NetworkMiner", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    this.networkAdaptersComboBox.SelectedIndex = 0;
                    this.startButton.Enabled = false;
                    this.startCapturingToolStripMenuItem.Enabled = false;
                }

            }

            else if (this.networkAdaptersComboBox.SelectedValue.GetType().Equals(typeof(NetworkWrapper.NullAdapter))) {
                this.startButton.Enabled = false;
                this.startCapturingToolStripMenuItem.Enabled = false;
            }
            else {
                throw new Exception("" + this.networkAdaptersComboBox.SelectedValue.GetType().ToString());
            }

        }

        private void button1_Click(object sender, EventArgs e) {
            this.framesTreeView.Nodes.Clear();
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e) {
            if (sniffer != null)
                sniffer.StopSniffing();
            this.Close();
        }


        private void loadCleartextDictionary(string dictionaryFile, bool enableDictionaryInPacketHandler) {
            if (this.InvokeRequired) {
                this.Invoke((MethodInvoker)delegate () { this.loadCleartextDictionary(dictionaryFile, enableDictionaryInPacketHandler); });
                /*
                GenericStringCallback callback = new GenericStringCallback(loadCleartextDictionary);
                this.Invoke(callback, dictionaryFile);
                */
            }
            else {
                System.IO.FileInfo dictionaryFileInfo;
                if (System.IO.File.Exists(dictionaryFile))
                    dictionaryFileInfo = new System.IO.FileInfo(dictionaryFile);
                else
                    dictionaryFileInfo = new System.IO.FileInfo(System.IO.Path.GetDirectoryName(System.Windows.Forms.Application.ExecutablePath) + System.IO.Path.DirectorySeparatorChar + "CleartextTools" + System.IO.Path.DirectorySeparatorChar + dictionaryFile);

                PacketParser.CleartextDictionary.WordDictionary d = new PacketParser.CleartextDictionary.WordDictionary();
                if (System.IO.File.Exists(dictionaryFileInfo.FullName)) {
                    if (enableDictionaryInPacketHandler) {
                        d.LoadDictionaryFile(dictionaryFileInfo.FullName);
                        packetHandlerWrapper.PacketHandler.Dictionary = d;
                    }
                    this.dictionaryNameLabel.Text = dictionaryFileInfo.Name;
                    this.dictionaryNameLabel.Tag = dictionaryFileInfo.FullName;
                }
                if (!enableDictionaryInPacketHandler)
                    packetHandlerWrapper.PacketHandler.Dictionary = d;
            }
                //this.showDetectedCleartextCheckBox.Enabled=true;
        }


        private void button1_Click_1(object sender, EventArgs e) {
            this.cleartextTextBox.Clear();
        }

        private void UpdateGuiControlsAfterParsingCompleteEventHandler(object sender, EventArgs e) {
            SharedUtils.Logger.Log("Updating GUI after PCAP parsing completed...", SharedUtils.Logger.EventLogEntryType.Information);
            //complete final calls to populate tabs
            try {
                if (this._guiProperties.UseVoipTab && this.VoipCallHandler != null)
                    foreach (VoipCall voipCall in this.VoipCallHandler.GetVoipCalls(this._guiProperties.ToCustomTimeZoneString))
                        this.voipDataGridView.Rows.Add(voipCall.CreateVoipCallDataGridViewRow());
            }
            catch(Exception ex) {
                MessageBox.Show(ex.Message, "Error in VoIP call extraction");
            }
            if(this.voipDataGridView.Rows.Count > 0)
                this.controlTextDictionary[this.tabPageVoIP] = "VoIP ("+ this.voipDataGridView.Rows.Count + ")";

            //add pending calls from timer
            this.GuiUpdateTimer_Tick(sender, e);
            //perform all queued control updates

            this.detectedHostsTreeRebuildButton_Click(this, new EventArgs());
            if (this._guiProperties.AutomaticallyResizeColumnsWhenParsingComplete) {
                this.resizeListViewColumns(this.filesListView);
                this.resizeListViewColumns(this.messagesListView);
                this.resizeListViewColumns(this.credentialsListView);
                this.resizeListViewColumns(this.sessionsListView);
                this.resizeListViewColumns(this.dnsListView);
                this.resizeListViewColumns(this.parametersListView);
                this.resizeListViewColumns(this.detectedKeywordsListView);
            }
            //update Tag in messagesListView to also include attachments so that they can be filtered/searched for
            foreach(ListViewItem messageItem in this.messagesListView.Items) {
                //look for Tag, extract MessageID and append name of each attachment to the list
                if (messageItem.Tag is Tuple<System.Collections.Specialized.NameValueCollection, byte[], Encoding> tuple) {
                    try {
                        string messageId = PacketParser.Mime.Email.GetMessageId(tuple.Item1);
                        if (this.messageAttachments.ContainsKey(messageId)) {
                            foreach (var attachment in this.messageAttachments[messageId]) {
                                tuple.Item1.Add(String.Empty, attachment.Filename);
                            }
                        }
                    }
                    catch {
                        //Pokemon exception handling, "Gotta catch 'em all"
                        SharedUtils.Logger.Log("Unable to index attachment for filtering.", SharedUtils.Logger.EventLogEntryType.Error);
                    }
                }
            }

            SharedUtils.Logger.Log("..done updating GUI.", SharedUtils.Logger.EventLogEntryType.Information);
        }

        private void detectedHostsTreeRebuildButton_Click(object sender, EventArgs e) {
            this.networkHostTreeView.Nodes.Clear();
            if (this.packetHandlerWrapper == null)
                return;//avoid using null

            if (this.packetHandlerWrapper.PacketHandler.NetworkHostList.Hosts.Count > 0) {
                //there might be errors if a host is added to the list during the period when this for-loop runs
                try {

                    PacketParser.NetworkHost[] sortedHostArray = null;

                    //The quick "golden hammer": http://csharpfeeds.com/post.aspx?id=5490
                    //lock (((System.Collections.ICollection)this.packetHandlerWrapper.PacketHandler.NetworkHostList.Hosts).SyncRoot) {
                    lock (this.packetHandlerWrapper.PacketHandler.NetworkHostList.Hosts) {

                        sortedHostArray = new PacketParser.NetworkHost[this.packetHandlerWrapper.PacketHandler.NetworkHostList.Hosts.Count];
                        this.packetHandlerWrapper.PacketHandler.NetworkHostList.Hosts.CopyTo(sortedHostArray, 0);
                    }

                    //now move all hosts to a sorted list which sorts on the right attribute
                    switch (this.GetHostSortOrderIndex()) {
                        case 0://IP
                            Array.Sort(sortedHostArray);
                            break;
                        case 1://MAC
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.MacAddressComparer());
                            break;
                        case 2://Hostname
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.HostNameComparer());
                            break;
                        case 3://Sent packets
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.SentPacketsComparer());
                            break;
                        case 4://Received packets
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.ReceivedPacketsComparer());
                            break;
                        case 5://Sent bytes
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.SentBytesComparer());
                            break;
                        case 6://Received bytes
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.ReceivedBytesComparer());
                            break;
                        case 7://Open ports count
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.OpenTcpPortsCountComparer());
                            break;
                        case 8://OS
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.OperatingSystemComparer());
                            break;
                        case 9://router hops
                            Array.Sort(sortedHostArray, new PacketParser.NetworkHost.TimeToLiveDistanceComparer());
                            break;
                    }



                    if (sortedHostArray != null && this.GuiProperties.UseHostsTab) {
                        this.AddNetworkHostsToTreeView(sortedHostArray);
                    }
                }
                catch (Exception ex) {
                    SharedUtils.Logger.Log("detectedHostsTreeRebuild: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                    this.networkHostTreeView.Nodes.Clear();//just to show that something went wrong...
                }
            }

        }


        private void openToolStripMenuItem_Click(object sender, EventArgs e) {
            //this.openFileDialog1.ShowDialog();

            if (this.openPcapFileDialog.ShowDialog() == DialogResult.OK) {
                this.LoadPcapFile(this.openPcapFileDialog.FileName, true);

            }
        }


        public void LoadPcapFilesSequentially(IList<string> filePathAndNameList, int offset = 0) {
            //TODO sequentially should really mean based on start time, not order in the list!
            if (filePathAndNameList != null && filePathAndNameList.Count > offset) {
                //TODO: take one at a time and load async then register a GetCompletedEvent callback to continue with the next file
                BackgroundWorker bw = this.LoadPcapFile(filePathAndNameList[offset], offset + 1 == filePathAndNameList.Count);
                if(bw == null) {
                    this.LoadPcapFilesSequentially(filePathAndNameList, offset + 1);
                }
                else if (filePathAndNameList.Count > offset + 1) {
                    bw.RunWorkerCompleted += (sender, eventArgs) => {
                        if (!eventArgs.Cancelled)
                            this.LoadPcapFilesSequentially(filePathAndNameList, offset + 1);
                    };
                }
            }

        }

        [System.Obsolete("LoadPcapFileBlocking is deprecated, please use LoadPcapFilesSequentially instead.")]
        public void LoadPcapFileBlocking(string filePathAndName) {
            BackgroundWorker bw = this.LoadPcapFile(filePathAndName, true);
            while (bw != null && bw.IsBusy) {
                if (bw.CancellationPending) {
                    break;
                }
                else {
                    Application.DoEvents();
                }
            }
        }

        /// <summary>
        /// Loads a pcap file into NetworkMiner
        /// </summary>
        /// <param name="filename">The full path and filename of the pcap file to open</param>
        public BackgroundWorker LoadPcapFile(string filePathAndName, bool refreshGuiAfterLoading, System.IO.FileShare fileShare = System.IO.FileShare.Read) {
            SharedUtils.Logger.Log("Loading " + filePathAndName, SharedUtils.Logger.EventLogEntryType.Information);
            /*
            if (filePathAndName.EndsWith(".pcap", StringComparison.InvariantCultureIgnoreCase) ||
                filePathAndName.EndsWith(".cap", StringComparison.InvariantCultureIgnoreCase) ||
                filePathAndName.EndsWith(".log", StringComparison.InvariantCultureIgnoreCase) ||
                filePathAndName.EndsWith(".dump", StringComparison.InvariantCultureIgnoreCase) ||
                filePathAndName.EndsWith(".dmp", StringComparison.InvariantCultureIgnoreCase) ||
                filePathAndName.EndsWith(".dat", StringComparison.InvariantCultureIgnoreCase) ||
                filePathAndName.EndsWith(".raw", StringComparison.InvariantCultureIgnoreCase) ||
                filePathAndName.Contains(".pcap") ||
                filePathAndName.Contains(".dmp")) {*/
            if (this.casePanelFileListView.Items.ContainsKey(filePathAndName))
                MessageBox.Show("File is already opened in the current case");
            else if(System.IO.File.Exists(filePathAndName)) {

                PcapFileReader pcapReader = null;
                try {
                    CaseFile caseFile = new CaseFile(filePathAndName);

                    pcapReader = new PcapFileReader(filePathAndName, this.pcapFileReaderQueueSize, new PcapFileReader.CaseFileLoadedCallback(this.caseFileLoaded), fileShare);
                    //pcapReader = new PcapFileReader(filePathAndName, this.pcapFileReaderQueueSize, new PcapFileReader.CaseFileLoadedCallback(this.caseFileLoaded));
                    if (pcapReader.PcapParser != null) {


                        LoadingProcess lp = new LoadingProcess(pcapReader, caseFile) {
                            StartPosition = FormStartPosition.CenterParent
                        };
                        lp.Show();
                        lp.Update();
                        BackgroundWorker fileWorker = new BackgroundWorker();
                        fileWorker.DoWork += new DoWorkEventHandler(this.fileWorker_DoWork);
                        //fileWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(detectedHostsTreeRebuildButton_Click);
                        if (refreshGuiAfterLoading)
                            fileWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(this.UpdateGuiControlsAfterParsingCompleteEventHandler);
                        fileWorker.WorkerSupportsCancellation = true;
                        lp.Worker = fileWorker;
                        fileWorker.RunWorkerAsync(lp);
                        this.AddPcapFileToCasePanel(caseFile, fileShare == System.IO.FileShare.Read || fileShare == System.IO.FileShare.None);//computes MD5

                        return fileWorker;
                    }
                }
                catch (System.IO.InvalidDataException ex) {
                    SharedUtils.Logger.Log("LoadPcapFile1: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                    if (ex.Message.Contains("Magic number is A0D0D0A"))
                        MessageBox.Show("This is a PcapNg file. NetworkMiner Professional is required to parse PcapNg files.\n\nNetworkMiner Professional can be purchased from Netresec's website:\nhttp://www.netresec.com/", "PcapNg Files Not Supported");
                    else
                        MessageBox.Show("Error opening PCAP file: " + ex.Message, "Invalid PCAP file");
                    if (pcapReader != null)
                        pcapReader.Dispose();
                }
                catch (System.UnauthorizedAccessException ex) {
                    SharedUtils.Logger.Log("LoadPcapFile2: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                    MessageBox.Show("Unauthorized to open file " + filePathAndName, "Unauthorized Access");
                    if (pcapReader != null)
                        pcapReader.Dispose();
                }
                catch (Exception ex) {
                    SharedUtils.Logger.Log("LoadPcapFile3: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                    MessageBox.Show("Error opening PCAP file: " + ex.Message, "Could not open PCAP file");

                    if (pcapReader != null)
                        pcapReader.Dispose();
                }
            }
            else if(System.IO.Directory.Exists(filePathAndName)) {
                MessageBox.Show("NetworkMiner can't open directories, try a PCAP file instead!", "Not a File");
            }

            return null;
        }

        void fileWorker_DoWork(object sender, DoWorkEventArgs e) {

            //extract the argument (LoadingProcess)
            LoadingProcess lp = (LoadingProcess)e.Argument;
            int percentRead = 0;

            using (PcapFileReader pcapReader = lp.PcapReader) {

                int parsingQueueMaxSize = this.pcapFileReaderQueueSize;
                int parsingQueueSignalSize = parsingQueueMaxSize / 20;//larger size = start parser earlier

                DateTime parsingStartTime = DateTime.Now;
                int enqueuedFramesSinceLastWait = 0;
                this.reloadCaseFilesButton.Invoke((MethodInvoker)delegate () { this.reloadCaseFilesButton.Enabled = false; });

                foreach (PcapFrame pcapPacket in pcapReader.PacketEnumerator()) {

                    try {
                        PacketParser.Frame frame = packetHandlerWrapper.PacketHandler.GetFrame(pcapPacket.Timestamp, pcapPacket.Data, pcapPacket.DataLinkType);
                        packetHandlerWrapper.PacketHandler.AddFrameToFrameParsingQueue(frame);
                        enqueuedFramesSinceLastWait++;
                        int newPercentRead = pcapReader.GetPercentRead(packetHandlerWrapper.PacketHandler.FramesToParseQueuedByteCount);
                        if (newPercentRead != percentRead) {
                            percentRead = newPercentRead;

                            try {
                                if (lp.Visible) {
                                    lp.Percent = percentRead;

                                    //lp.Invoke((EmptyDelegateCallback)delegate () { lp.Percent = percentRead; });
                                    //lp.Invoke(new EmptyDelegateCallback(lp.Update));
                                }
                            }
                            catch (Exception) {
                                break;
                            }
                        }
                    }
                    catch (Exception frameException) {
                        SharedUtils.Logger.Log(frameException.GetType().ToString() + " when reading frame: " + frameException.Message, SharedUtils.Logger.EventLogEntryType.Error);
#if DEBUG
                        throw frameException;
#endif
                    }
                }
                SharedUtils.Logger.Log(lp.CaseFile.Filename + " frames read in " + DateTime.Now.Subtract(parsingStartTime).ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                lp.CaseFile.AddMetadata(pcapReader.PcapParserMetadata);

                while (packetHandlerWrapper.PacketHandler.FramesInQueue > 0) {//just to make sure we dont finish too early
                    System.Threading.Thread.Sleep(200);
                    int newPercentRead = pcapReader.GetPercentRead(packetHandlerWrapper.PacketHandler.FramesToParseQueuedByteCount);
                    if (newPercentRead != percentRead) {
                        percentRead = newPercentRead;

                        try {
                            if (lp.Visible) {
                                lp.Percent = percentRead;
                            }
                        }
                        catch (Exception) {
                            break;
                        }
                    }
                }
                TimeSpan parsingTimeTotal = DateTime.Now.Subtract(parsingStartTime);
                lp.CaseFile.ParsingTime = parsingTimeTotal;
                SharedUtils.Logger.Log(lp.CaseFile.Filename + " parsed in " + lp.CaseFile.ParsingTime.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
            }
            try {
                lp.Invoke(new EmptyDelegateCallback(lp.Close));
            }
            catch (Exception ex) {
                SharedUtils.Logger.Log("fileWorker_DoWork: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
            }//the form might already be closed

            this.reloadCaseFilesButton.Invoke((MethodInvoker)delegate () { this.reloadCaseFilesButton.Enabled = true; });
        }


        private void openFileDialog1_FileOk(object sender, CancelEventArgs e) {
            /*

             * */
        }

        private void resetCapturedDataToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ResetCapturedData(true, true);
        }

        private void ResetCapturedData(bool removeCapturedFiles, bool clearIpColorHandler) {
            this.networkHostTreeView.Nodes.Clear();
            this.macToTreeNodeDictionary.Clear();
            this.framesTreeView.Nodes.Clear();
            this.imagesListView.Items.Clear();
            this.imageList.Images.Clear();
            this.messagesListView.Items.Clear();
            this.messageAttributeListView.Items.Clear();
            this.messagesKeywordFilterControl.Clear();
            this.messageAttachmentListView.Items.Clear();
            this.SetTextBoxText(this.messageTextBox, "[no message selected]");
            //this.messageTextBox.Text="[no message selected]";
            this.sessionsKeywordFilterControl.Clear();
            this.filesKeywordFilterControl.Clear();
            this.filesListView.Items.Clear();
            this.credentialsListView.Items.Clear();
            this.sessionsListView.Items.Clear();
            this.dnsKeywordFilterControl.Clear();
            this.dnsListView.Items.Clear();
            this.parametersKeywordFilterControl.Clear();
            this.parametersListView.Items.Clear();
            this.httpTransactionTreeView.Nodes.Clear();
            this.detectedKeywordsListView.Items.Clear();
            this.cleartextTextBox.Clear();
            this.anomalyLog.Clear();
            this.casePanelFileListView.Items.Clear();
            this.messageAttachments.Clear();
            this.voipDataGridView.Rows.Clear();


            this.controlTextDictionary[this.tabPageDetectedHosts] = "Hosts";
            this.controlTextDictionary[this.tabPageReceivedFrames] = "Frames";
            this.controlTextDictionary[this.tabPageFiles] = "Files";
            this.controlTextDictionary[this.tabPageImages] = "Images";
            this.controlTextDictionary[this.tabPageMessages] = "Messages";
            this.controlTextDictionary[this.tabPageCredentials] = "Credentials";
            this.controlTextDictionary[this.tabPageVoIP] = "VoIP";
            this.controlTextDictionary[this.tabPageSessions] = "Sessions";
            this.controlTextDictionary[this.tabPageDns] = "DNS";
            this.controlTextDictionary[this.tabPageParameters] = "Parameters";
            this.controlTextDictionary[this.tabPageBrowsers] = "Browsers";


            this.packetHandlerWrapper.ResetCapturedData();
            //this.nFilesReceived=0;

            if (removeCapturedFiles) {
                PacketParser.FileTransfer.FileStreamAssemblerList.RemoveTempFiles();
                string capturesDirectory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath)) + System.IO.Path.DirectorySeparatorChar + "Captures";
                if (System.IO.Directory.Exists(capturesDirectory)) {
                    foreach (string pcapFile in System.IO.Directory.GetFiles(capturesDirectory))
                        try {
                            System.IO.File.Delete(pcapFile);
                        }
                        catch {
                            this.anomalyQueue.Enqueue(new PacketParser.Events.AnomalyEventArgs("Error deleting file \"" + pcapFile + "\"", DateTime.Now));
                            //this.ShowAnomaly("Error deleting file \"" + pcapFile + "\"", DateTime.Now);
                        }
                }
                capturesDirectory = this.packetHandlerWrapper.PacketHandler.OutputDirectory + "Captures";
                if (System.IO.Directory.Exists(capturesDirectory)) {
                    foreach (string pcapFile in System.IO.Directory.GetFiles(capturesDirectory))
                        try {
                            System.IO.File.Delete(pcapFile);
                        }
                        catch {
                            this.anomalyQueue.Enqueue(new PacketParser.Events.AnomalyEventArgs("Error deleting file \"" + pcapFile + "\"", DateTime.Now));
                            //this.ShowAnomaly("Error deleting file \"" + pcapFile + "\"", DateTime.Now);
                        }
                }
            }

            if (this._ipColorHandler != null) {
                this._ipColorHandler.Clear();
                if (clearIpColorHandler)
                    this._ipColorHandler.RemoveColors(false);
            }
            this.UpdateGuiControlsAfterParsingCompleteEventHandler(this, null);
            this.GuiCleared?.Invoke(this, new EventArgs());
        }

        private void aboutNetworkMinerToolStripMenuItem_Click(object sender, EventArgs e) {
            //new NetworkMinerAboutBox(this.productLink, this.aboutText).ShowDialog();
            new NetworkMinerAboutBox(this.productLink, this.aboutText).ShowDialog();
        }


        private ListViewItem createDetectedKeywordItem(PacketParser.Frame frame, int keywordIndex, int keywordLength, PacketParser.NetworkHost sourceHost, PacketParser.NetworkHost destinationHost, string sourcePort, string destinationPort) {
            string[] itemData = new string[8];
            itemData[0] = frame.FrameNumber.ToString();
            itemData[1] = this._guiProperties.ToCustomTimeZoneString(frame.Timestamp);//.ToString();
            //byte[] keyword=new byte[keywordLength];
            //Array.Copy(frame.Data, keywordIndex, keyword, 0, keywordLength);
            string keywordString = "";
            string keywordHexString = "";
            for (int i = 0; i < keywordLength; i++) {
                keywordString += (char)frame.Data[keywordIndex + i];
                keywordHexString += frame.Data[keywordIndex + i].ToString("X2");
            }
            itemData[2] = System.Text.RegularExpressions.Regex.Replace(keywordString, @"[^ -~]", ".") + " [0x" + keywordHexString + "]";//regex from Eric Gunnerson's blog (which is really good)

            itemData[3] = PacketParser.Utils.StringManglerUtil.GetReadableContextString(frame.Data, keywordIndex, keywordLength);
            if (sourceHost != null)
                itemData[4] = sourceHost.ToString();
            itemData[5] = sourcePort;
            if (destinationHost != null)
                itemData[6] = destinationHost.ToString();
            itemData[7] = destinationPort;
            ListViewItem item = new ListViewItem(itemData);


            if (this._ipColorHandler != null) {
                this._ipColorHandler.Colorize(sourceHost.IPAddress, item);
                this._ipColorHandler.Colorize(destinationHost.IPAddress, item);
            }

#if DEBUG
            if (this.InvokeRequired)
                System.Diagnostics.Debugger.Break();
#endif
            return item;

            //Inv oke(new AddItemToListView(this.detectedKeywordsListView.Items.Add), item);
        }


        private void addKeyword(object sender, EventArgs e) {
            string errorMessage;
            if (this.TryAddKeywordToListBox(this.keywordTextBox.Text, out errorMessage)) {
                this.keywordTextBox.Text = "";
                packetHandlerWrapper.UpdateKeywords((System.Collections.IEnumerable)this.keywordListBox.Items);
                
            }
            else
                MessageBox.Show(errorMessage);
        }


        private bool TryAddKeywordToListBox(string keyword, out string errorMessage) {
            if (keyword.Length < 3) {
                errorMessage = "Keywords must be at least 3 bytes long to avoid false positives";
                return false;
            }
            else {

                if (this.keywordTextBox.Text.StartsWith("0x")) {//hex string
                    try {
                        PacketParser.Utils.ByteConverter.ToByteArrayFromHexString(keyword);//to force valid hex
                        this.keywordListBox.Items.Add(keyword);
                        //Lägg till keywordet till PacketHandler.PacketHandler!!!
                    }
                    catch (Exception ex) {
                        errorMessage = ex.Message;
                        return false;
                    }
                }
                else {//normal string
                    this.keywordListBox.Items.Add(keyword);

                }
                if (this.casePanelFileListView.Items.Count > 0 && !this.keywordWarningMessageShown) {
                    MessageBox.Show("Please add keywords before loading a PCAP file, or press \"Reload Case Files\" after adding keywords.", "Reload Case Files Required");
                    this.keywordWarningMessageShown = true;
                }
                errorMessage = null;
                return true;

            }
        }

        private void removeKeywordButton_Click(object sender, EventArgs e) {
            List<object> objectsToRemove = new List<object>();
            foreach (object o in this.keywordListBox.SelectedItems)
                objectsToRemove.Add(o);
            foreach (object o in objectsToRemove)
                this.keywordListBox.Items.Remove(o);
            packetHandlerWrapper.UpdateKeywords((System.Collections.IEnumerable)this.keywordListBox.Items);
        }

#region ListViewSorting
        //from: ms-help://MS.VSCC.v80/MS.MSDN.v80/MS.NETDEVFX.v20.en/CPref17/html/P_System_Windows_Forms_ListView_ListViewItemSorter.htm

        private void ListViewColumnClick(object o, ColumnClickEventArgs e) {
            // Set the ListViewItemSorter property to a new ListViewItemComparer 
            // object. Setting this property immediately sorts the 
            // ListView using the ListViewItemComparer object.

            //made generic with help from: http://www.codeproject.com/KB/list/BindSortAutosizing.aspx
            ListView sortListView = (ListView)o;

            sortListView.ListViewItemSorter = new ListViewItemComparer(e.Column);// .ListViewItemSorter = new ListViewItemComparer(e.Column);

        }


        // Implements the manual sorting of items by columns.
        class ListViewItemComparer : System.Collections.IComparer {
            private int col;
            public ListViewItemComparer() {
                col = 0;
            }
            public ListViewItemComparer(int column) {
                col = column;
            }
            public int Compare(ListViewItem x, ListViewItem y) {
                //first check if we might have numbered values
                string xText = x.SubItems[col].Text;
                string yText = y.SubItems[col].Text;

                //int xInt, yInt;
                if (xText.Length > 0 && yText.Length > 0) {
                    if (Char.IsNumber(xText[0]) && Char.IsNumber(yText[0])) {
                        //we have two numbers!
                        //see which one is largest
                        double xDouble = PacketParser.Utils.ByteConverter.StringToClosestDouble(xText);
                        double yDouble = PacketParser.Utils.ByteConverter.StringToClosestDouble(yText);
                        if (xDouble < yDouble)
                            return (int)(xDouble - yDouble - 1);
                        else if (xDouble > yDouble)
                            return (int)(xDouble - yDouble + 1);
                    }
                    //if not just compare them normally
                }
                return String.Compare(x.SubItems[col].Text, y.SubItems[col].Text);
            }
            public int Compare(object x, object y) {
                return Compare((ListViewItem)x, (ListViewItem)y);
                //return String.Compare(((ListViewItem)x).SubItems[col].Text, ((ListViewItem)y).SubItems[col].Text);
            }

        }
#endregion

        private void hostSortOrderComboBox_SelectedIndexChanged(object sender, EventArgs e) {
            //HÄR SKA detailsHeader LIGGA Enabled MASSA OLIKA SORTERINGSORDNINGAR:
            //IP, HOTSNAME, SENT PACKETS, RECEIVED PACKETS, MAC ADDRESS
            this.detectedHostsTreeRebuildButton_Click(sender, e);
        }

        private void NetworkMinerForm_FormClosed(object sender, FormClosedEventArgs e) {
            //packetHandlerThread.Abort();
            packetHandlerWrapper.AbortBackgroundThreads();
        }

        private void NetworkMinerForm_FormClosing(object sender, FormClosingEventArgs e) {
            stopButton_Click(sender, e);
            PacketParser.FileTransfer.FileStreamAssemblerList.RemoveTempFiles();
        }

        //http://blogs.techrepublic.com.com/howdoi/?p=148
        private void NetworkMinerForm_DragEnter(object sender, DragEventArgs e) {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) {
                string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (files?.Count() > 0 && !AllPathsAreInAssembledFilesDirectory(files)) {
                    e.Effect = DragDropEffects.Copy;
                    SharedUtils.Logger.Log("Drag-and-Drop: " + String.Concat<string>(files), SharedUtils.Logger.EventLogEntryType.Information);
                }
                else
                    e.Effect = DragDropEffects.None;
            }
            else
                e.Effect = DragDropEffects.None;
        }

        private bool AllPathsAreInAssembledFilesDirectory(string[] paths) {
            foreach (string p in paths) {
                if (!p.Contains(PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY))
                    return false;
                if (!this.IsSubDirectoryOf(new System.IO.DirectoryInfo(p), new System.IO.DirectoryInfo(this.packetHandlerWrapper.PacketHandler.OutputDirectory + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY)))
                    return false;
            }
            return true;
        }
        private bool IsSubDirectoryOf(System.IO.DirectoryInfo path, System.IO.DirectoryInfo directory) {
            if (path.FullName.TrimEnd(System.IO.Path.DirectorySeparatorChar) == directory.FullName.TrimEnd(System.IO.Path.DirectorySeparatorChar))
                return true;
            else if (path.FullName.Length < directory.FullName.Length)
                return false;
            else if (path.Parent == null)
                return false;
            else return IsSubDirectoryOf(path.Parent, directory);

        }

        //http://blogs.techrepublic.com.com/howdoi/?p=148
        private void NetworkMinerForm_DragDrop(object sender, DragEventArgs e) {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) {
                string[] filenames = (string[])e.Data.GetData(DataFormats.FileDrop);
                Array.Sort<string>(filenames);
                this.LoadPcapFilesSequentially(filenames);
            }
        }

        private void cleartextSearchModeComboBox_SelectedIndexChanged(object sender, EventArgs e) {
            if(this.packetHandlerWrapper != null)
                this.packetHandlerWrapper.CleartextSearchModeSelectedIndex = this.cleartextSearchModeComboBox.SelectedIndex;
        }

        private void keywordListBox_ControlAdded(object sender, ControlEventArgs e) {
            packetHandlerWrapper.UpdateKeywords((System.Collections.IEnumerable)this.keywordListBox.Items);
        }

        private void keywordListBox_ControlRemoved(object sender, ControlEventArgs e) {
            packetHandlerWrapper.UpdateKeywords((IEnumerable<string>)this.keywordListBox.Items);
        }

        private void reloadCaseFilesButton_Click(object sender, EventArgs e) {
            List<string> files = new List<string>(this.casePanelFileListView.Items.Count);
            foreach (ListViewItem fileItem in this.casePanelFileListView.Items)
                files.Add(fileItem.Name);

            this.ResetCapturedData(false, false);

            this.LoadPcapFilesSequentially(files);


        }

        private void removeCaseFileMenuItem_Click(object sender, EventArgs e) {
            ListView.SelectedListViewItemCollection itemsToRemove = this.casePanelFileListView.SelectedItems;
            foreach (ListViewItem item in itemsToRemove)
                this.casePanelFileListView.Items.Remove(item);
        }

        private void clearAnomaliesButton_Click(object sender, EventArgs e) {
            this.anomalyLog.Clear();
        }

        private void openParentFolderToolStripMenuItem_Click(object sender, EventArgs e) {

            if (casePanelFileListView.SelectedItems.Count > 0) {
                CaseFile caseFile = (CaseFile)casePanelFileListView.SelectedItems[0].Tag;
                //string filePath=caseFile.FilePathAndName;//.Text;
                string folderPath = caseFile.FilePathAndName;
                if (caseFile.FilePathAndName.Contains(System.IO.Path.DirectorySeparatorChar.ToString()))
                    folderPath = caseFile.FilePathAndName.Substring(0, caseFile.FilePathAndName.LastIndexOf(System.IO.Path.DirectorySeparatorChar) + 1);
                //System.Diagnostics.Process.Start(folderPath);
                SharedUtils.SystemHelper.ProcessStart(folderPath);
            }
        }

        private void printReportToolStripMenuItem_Click(object sender, EventArgs e) {
            if (this.reportGenerator != null)
                this.reportGenerator.ShowReport(this);
            else
                MessageBox.Show("Not implemented");
        }

        private void selectHostColorMenuItem_Click(object sender, EventArgs e) {
            if (this._ipColorHandler == null) {
                MessageBox.Show("Please enable host coloring in: Tools > Settings", "Host Coloring Not Enabled");
            }
            else {
                if (this.colorDialog1.ShowDialog() == DialogResult.OK) {
                    TreeNode n = this.networkHostTreeView.SelectedNode;
                    while (n != null && n.GetType() != typeof(NetworkHostTreeNode)) {
                        n = n.Parent;
                    }
                    if (this._ipColorHandler != null && n != null) {
                        NetworkHostTreeNode node = (NetworkHostTreeNode)n;
                        //this.ipColors[node.NetworkHost.IPAddress]=this.colorDialog1.Color;
                        //node.BackColor=this.colorDialog1.Color;
                        this._ipColorHandler.AddColor(node.NetworkHost.IPAddress, this.colorDialog1.Color);
                        if (this._ipColorHandler.ReloadRequired) {
                            this._ipColorHandler.Colorize(node.NetworkHost.IPAddress, node);
                            if (this._ipColorHandler.Keys.Count < 2)
                                MessageBox.Show("You need to press \"Reload Case Files\" to update the colors in other tabs");
                        }

                    }
                }
            }
        }
        private void removeHostColorToolStripMenuItem_Click(object sender, EventArgs e) {
            TreeNode n = this.networkHostTreeView.SelectedNode;
            while (n != null && n.GetType() != typeof(NetworkHostTreeNode)) {
                n = n.Parent;
            }
            if (n != null && this._ipColorHandler != null) {
                NetworkHostTreeNode node = (NetworkHostTreeNode)n;

                this._ipColorHandler.RemoveColor(node.NetworkHost.IPAddress);

                if (this._ipColorHandler.ReloadRequired) {
                    node.BackColor = new Color();//a "Reload Case Files" is required
                    MessageBox.Show("You need to press \"Reload Case Files\" to update the colors in other tabs");
                }
            }
        }

        /*
        private void networkHostTreeView_MouseDown(object sender, MouseEventArgs e) {
            //http://www.knightoftheroad.com/post/2008/02/Treeview-tight-click-select.aspx
            if (e.Button != MouseButtons.None) {
                networkHostTreeView.SelectedNode = networkHostTreeView.GetNodeAt(e.X, e.Y);
                if (e.Button == MouseButtons.Right) {
                    TreeNode n = this.networkHostTreeView.SelectedNode;
                    while (n != null && n.GetType() != typeof(NetworkHostTreeNode)) {
                        n = n.Parent;
                    }
                    if (n != null) {
                        lock (this.hostMenuStrip) {
                            foreach (ToolStripMenuItem item in this.hostMenuStripExtraItems)
                                this.hostMenuStrip.Items.Remove(item);
                            //List<ToolStripMenuItem> newHostMenuStripExtraItems = new List<ToolStripMenuItem>();
                            this.hostMenuStripExtraItems.Clear();
                            NetworkHostTreeNode node = (NetworkHostTreeNode)n;
                            this.hostMenuStripExtraItems.Add(this.GetIpLookupToolStripMenuItem(node.NetworkHost.IPAddress, node.NetworkHost.SentPackets.FirsPacketTimestamp));
                            foreach (string domain in node.NetworkHost.HostNames)
                                this.hostMenuStripExtraItems.Add(this.GetDomainLookupToolStripMenuItem(domain));
                            this.hostMenuStrip.Items.AddRange(this.hostMenuStripExtraItems.ToArray());
                            //this.hostMenuStripExtraItems = newHostMenuStripExtraItems;
                        }
                    }
                }
                
            }
        }*/

        private void networkHostTreeView_NodeMouseClick(object sender, TreeNodeMouseClickEventArgs e) {
            //http://www.knightoftheroad.com/post/2008/02/Treeview-tight-click-select.aspx
            if (e.Button != MouseButtons.None) {
                networkHostTreeView.SelectedNode = e.Node;
                if (e.Button == MouseButtons.Right) {
                    TreeNode n = this.networkHostTreeView.SelectedNode;
                    while (n != null && n.GetType() != typeof(NetworkHostTreeNode)) {
                        n = n.Parent;
                    }
                    if (n != null) {
                        lock (this.hostMenuStrip) {
                            foreach (ToolStripMenuItem item in this.hostMenuStripExtraItems)
                                this.hostMenuStrip.Items.Remove(item);
                            //List<ToolStripMenuItem> newHostMenuStripExtraItems = new List<ToolStripMenuItem>();
                            this.hostMenuStripExtraItems.Clear();
                            NetworkHostTreeNode node = (NetworkHostTreeNode)n;
                            this.hostMenuStripExtraItems.Add(this.GetIpLookupToolStripMenuItem(node.NetworkHost.IPAddress, node.NetworkHost.SentPackets.FirsPacketTimestamp));
                            foreach (string domain in node.NetworkHost.HostNames)
                                this.hostMenuStripExtraItems.Add(this.GetDomainLookupToolStripMenuItem(domain));
                            //GetJa3HashLookupToolStripMenuItem
                            foreach(string ja3 in node.NetworkHost.Ja3Hashes)
                                this.hostMenuStripExtraItems.Add(this.GetJa3HashLookupToolStripMenuItem(ja3));
                            this.hostMenuStrip.Items.AddRange(this.hostMenuStripExtraItems.ToArray());
                            //this.hostMenuStripExtraItems = newHostMenuStripExtraItems;
                        }
                    }
                }

            }
        }

        private void hostColorMenuStrip_Opening(object sender, CancelEventArgs e) {
            TreeNode n = this.networkHostTreeView.SelectedNode;
            while (n != null && n.GetType() != typeof(NetworkHostTreeNode)) {
                n = n.Parent;
            }
            if (n != null && this._ipColorHandler != null) {
                NetworkHostTreeNode node = (NetworkHostTreeNode)n;
                if (this._ipColorHandler.Keys.Contains(node.NetworkHost.IPAddress))
                    this.removeHostColorToolStripMenuItem.Enabled = true;
                else
                    this.removeHostColorToolStripMenuItem.Enabled = false;
            }
        }

        private void copyParameterNameToolStripMenuItem_Click(object sender, EventArgs e) {
            if (this.parametersListView.SelectedItems.Count > 0) {
                System.Collections.Generic.KeyValuePair<string, string> nameValueTag = (System.Collections.Generic.KeyValuePair<string, string>)this.parametersListView.SelectedItems[0].Tag;
                Clipboard.SetDataObject(nameValueTag.Key, true);
            }

        }

        private void copyParameterValueToolStripMenuItem_Click(object sender, EventArgs e) {
            if (this.parametersListView.SelectedItems.Count > 0) {
                System.Collections.Generic.KeyValuePair<string, string> nameValueTag = (System.Collections.Generic.KeyValuePair<string, string>)this.parametersListView.SelectedItems[0].Tag;
                Clipboard.SetDataObject(nameValueTag.Value, true);
            }
        }

        private void copyTextToolStripMenuItem_Click(object sender, EventArgs e) {
            TreeNode n = this.networkHostTreeView.SelectedNode;
            if (n != null) {
                Clipboard.SetDataObject(n.Text, true);
            }
        }

        private void CopySelectedListViewItemTagToClipBoard(object sender, EventArgs e) {
            if(sender is ToolStripMenuItem menuItem) {
                var control = menuItem?.GetCurrentParent()?.TopLevelControl;
                if (control != null && control is ListView)
                    this.CopySelectedListViewItemTagToClipBoard(control, e);
                else if (this.filesListView.ContextMenuStrip == control)
                    this.CopySelectedListViewItemTagToClipBoard(this.filesListView, e);
#if DEBUG
                else
                    System.Diagnostics.Debugger.Break();//TODO add handler for new list views
#endif
            }
            else if(sender is ListView lv) {
                object tag = lv.SelectedItems[0]?.Tag;
                if(tag != null) {
                    Clipboard.SetDataObject(tag, true);
                }
            }
        }

        private void caseFileLoaded(string filePathAndName, int packetsCount, DateTime firstFrameTimestamp, DateTime lastFrameTimestamp) {
            //ensure that the correct thread is performing the operation
            if (this.casePanelFileListView.InvokeRequired) {
                object[] args = new object[4];
                args[0] = filePathAndName;
                args[1] = packetsCount;
                args[2] = firstFrameTimestamp;
                args[3] = lastFrameTimestamp;
                PcapFileReader.CaseFileLoadedCallback cDelegate = new PcapFileReader.CaseFileLoadedCallback(caseFileLoaded);
                this.BeginInvoke(cDelegate, args);
            }
            else {
                //set the CaseFile data
                foreach (ListViewItem item in this.casePanelFileListView.Items) {
                    if (item.Tag != null) {
                        CaseFile caseFile = (CaseFile)item.Tag;
                        if (caseFile.FilePathAndName == filePathAndName) {
                            caseFile.FirstFrameTimestamp = firstFrameTimestamp;
                            caseFile.LastFrameTimestamp = lastFrameTimestamp;
                            caseFile.FramesCount = packetsCount;
                            //item.ToolTipText = caseFile.FilePathAndName + "\nStart : " + caseFile.FirstFrameTimestamp.ToString() + "\nEnd : " + caseFile.LastFrameTimestamp.ToString() + "\nFrames : " + caseFile.FramesCount;
                            item.ToolTipText = caseFile.FilePathAndName + "\nStart : " + this._guiProperties.ToCustomTimeZoneString(caseFile.FirstFrameTimestamp) + "\nEnd : " + this._guiProperties.ToCustomTimeZoneString(caseFile.LastFrameTimestamp) + "\nFrames : " + caseFile.FramesCount;
                            
                            //item.SubItems.Add(caseFile.ParsingTime.ToString());
                        }
                    }
                }
            }
        }

        private void messagesListView_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e) {
            //Value string MUST be UTF8 encoded!
            //KeyValuePair<System.Collections.Specialized.NameValueCollection, byte[]> attributesAndMessage = (KeyValuePair<System.Collections.Specialized.NameValueCollection, byte[]>)e.Item.Tag;
            Tuple<System.Collections.Specialized.NameValueCollection, byte[], Encoding> attributesMessageEncodingTuple = (Tuple<System.Collections.Specialized.NameValueCollection, byte[], Encoding>)e.Item.Tag;

            this.messageAttributeListView.Items.Clear();
            this.messageAttachmentListView.Items.Clear();

            //this.messageAttributesTreeView.Nodes.Clear();
            //string messageId = PacketParser.Mime.Email.GetFileId(attributesAndMessage.Key);
            string messageId = PacketParser.Mime.Email.GetMessageId(attributesMessageEncodingTuple.Item1);
            if (messageId != null && messageId.Length > 0) {
                lock (this.messageAttachments) {
                    if (this.messageAttachments.ContainsKey(messageId)) {
                        foreach (PacketParser.FileTransfer.ReconstructedFile attachment in this.messageAttachments[messageId]) {
                            if (e.Item.SubItems[1].Text.StartsWith(attachment.SourceHost.IPAddress.ToString()) && e.Item.SubItems[2].Text.StartsWith(attachment.DestinationHost.IPAddress.ToString())) {
                                //this.messageAttachmentListView.Items.Add(attachment.Filename + " ( " + attachment.FileSizeString + ")");
                                ListViewItem attachmentItem = new ListViewItem(
                                    new string[] {
                                        attachment.Filename,
                                        attachment.FileSizeString
                                    });

                                //ListViewItem attachmentItem = this.messageAttachmentListView.Items.Add(attachment.FilePath, attachment.Filename);
                                //attachmentItem.SubItems.Add(attachment.FileSizeString);
                                attachmentItem.Tag = attachment.FilePath;//must use path here so that I can reuse drag-and-drop routines for Files tab
                                attachmentItem.ToolTipText = attachment.FilePath;
                                this.messageAttachmentListView.Items.Add(attachmentItem);
                            }
                        }
                    }
                }
            }



            this.messageAttributeListView.Items.AddRange(attributesMessageEncodingTuple.Item1.AllKeys.Where(name => name?.Length > 0).Select(attributeName => {
                ListViewItem lvi = new ListViewItem(attributeName);
                lvi.SubItems.Add(attributesMessageEncodingTuple.Item1[attributeName]);
                return lvi;
            }).ToArray());


            if (attributesMessageEncodingTuple.Item3 != null) {
                EncodingWrapper encodingItem = this.messageEncodingComboBox.Items?.OfType<EncodingWrapper>()?.Where(i => i.Encoding == attributesMessageEncodingTuple.Item3).FirstOrDefault();
                if(encodingItem == null) {
                    //try adding it
                    lock(this.messageEncodingComboBox) {
                        SharedUtils.Logger.Log("Adding message encoding option for " + attributesMessageEncodingTuple.Item3.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                        try {
                            this.messageEncodingComboBox.Items.Add(new EncodingWrapper(attributesMessageEncodingTuple.Item3));
                        }
                        catch (Exception ee) {
                            SharedUtils.Logger.Log(ee.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                        }
                        encodingItem = this.messageEncodingComboBox.Items?.OfType<EncodingWrapper>()?.Where(i => i.Encoding == attributesMessageEncodingTuple.Item3).FirstOrDefault();
                    }
                }
                if (encodingItem != null)
                    this.messageEncodingComboBox.SelectedItem = encodingItem;

                //this.SetTextBoxText(this.messageTextBox, attributesMessageEncodingTuple.Item2, attributesMessageEncodingTuple.Item3);
            }

            if (this.messageEncodingComboBox.SelectedItem is EncodingWrapper) {
                EncodingWrapper ew = this.messageEncodingComboBox.SelectedItem as EncodingWrapper;
                this.SetTextBoxText(this.messageTextBox, attributesMessageEncodingTuple.Item2, ew.Encoding);
                //this.messageTextBox.Text = ew.Encoding.GetString(Encoding.Default.GetBytes(attributesAndMessage.Value));
            }
            else
                this.SetTextBoxText(this.messageTextBox, attributesMessageEncodingTuple.Item2, Encoding.Default);

        }

        private void SetTextBoxText(TextBox tb, string encodedString) {
            this.SetTextBoxText(tb, Encoding.Default.GetBytes(encodedString), Encoding.Default);
        }

        private void SetTextBoxText(TextBox tb, byte[] bytes, Encoding enc) {
            tb.Text = enc.GetString(bytes);
            //check line ending, in Windows: replace \n with \r\n, in Linux replace \r\n with \n
            tb.Text = PacketParser.Utils.StringManglerUtil.ChangeToEnvironmentNewLines(tb.Text);

            tb.Tag = bytes;
        }

        private void ShowExportToFileDialog(ListView listView, string basename) {
            try {
                if (this.DataExporterFactory != null) {
                    this.exportDataToFileDialog.FileName = basename + this.exportDataToFileDialog.DefaultExt;
                    if (this.exportDataToFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK) {

                        List<CaseFile> caseFiles = new List<CaseFile>();
                        foreach(ListViewItem fileItem in casePanelFileListView.Items) {
                            if (fileItem.Tag != null && fileItem.Tag is CaseFile)
                                caseFiles.Add(fileItem.Tag as CaseFile);
                        }

                        using (ToolInterfaces.IDataExporter exporter = this.DataExporterFactory.CreateDataExporter(this.exportDataToFileDialog.FileName, this.UseRelativeExtractedFilesPaths, this._guiProperties.PreserveLinesInCsvExport)) {
                            try {
                                exporter.Export(listView, true, caseFiles);
                            }
                            catch (NotImplementedException e) {
                                MessageBox.Show(e.Message, "Not implemented");
                            }
                        }
                    }
                }
                else
                    MessageBox.Show("Not implemented");
            }
#if !DEBUG
            catch (Exception ex) {
                MessageBox.Show(ex.Message);
            }
#endif
            finally { }
        }

        private void ShowExportToFileDialog(DataGridView dgv, string basename) {
            try {
                if (this.DataExporterFactory != null) {
                    this.exportDataToFileDialog.FileName = basename + this.exportDataToFileDialog.DefaultExt;
                    if (this.exportDataToFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK) {

                        List<CaseFile> caseFiles = new List<CaseFile>();
                        foreach (ListViewItem fileItem in casePanelFileListView.Items) {
                            if (fileItem.Tag != null && fileItem.Tag is CaseFile)
                                caseFiles.Add(fileItem.Tag as CaseFile);
                        }

                        using (ToolInterfaces.IDataExporter exporter = this.DataExporterFactory.CreateDataExporter(this.exportDataToFileDialog.FileName, this.UseRelativeExtractedFilesPaths, this._guiProperties.PreserveLinesInCsvExport)) {
                            try {
                                exporter.Export(dgv, true, caseFiles);
                            }
                            catch (NotImplementedException e) {
                                MessageBox.Show(e.Message, "Not implemented");
                            }
                        }
                    }
                }
                else
                    MessageBox.Show("Not implemented");
            }
#if !DEBUG
            catch (Exception ex) {
                MessageBox.Show(ex.Message);
            }
#endif
            finally { }
        }

        private void credentialsToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ShowExportToFileDialog(this.credentialsListView, "credentials");
        }

        private void dnsRecordsToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ShowExportToFileDialog(this.dnsListView, "dns");
        }

        private void fileInfosToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ShowExportToFileDialog(this.filesListView, "files");
        }

        private void voIPToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ShowExportToFileDialog(this.voipDataGridView, "voip");
        }

        private void hostsToolStripMenuItem_Click(object sender, EventArgs e) {
            try {
                if (this.DataExporterFactory != null) {
                    this.exportDataToFileDialog.FileName = "hosts" + this.exportDataToFileDialog.DefaultExt;
                    if (this.exportDataToFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK) {

                        using (ToolInterfaces.IDataExporter exporter = this.DataExporterFactory.CreateDataExporter(this.exportDataToFileDialog.FileName, this.UseRelativeExtractedFilesPaths, this._guiProperties.PreserveLinesInCsvExport)) {
                            foreach (NetworkHostTreeNode host in this.networkHostTreeView.Nodes) {
                                //NetworkHostTreeNode host = (NetworkHostTreeNode)n;

                                List<string> items = new List<string>();
                                items.Add(host.Text);

                                host.BeforeExpand();//to make sure all tags are set

                                foreach (TreeNode child in host.Nodes)
                                    if (child.Tag != null && child.Tag.GetType() == typeof(string))
                                        items.Add((string)child.Tag);

                                exporter.Export(items);

                            }
                        }
                    }
                }
                else
                    MessageBox.Show("Not implemented");
            }
            catch (Exception ex) {
                MessageBox.Show(ex.Message);
            }

        }

        private void messagesToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ShowExportToFileDialog(this.messagesListView, "messages");
        }

        private void parametersToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ShowExportToFileDialog(this.parametersListView, "parameters");
        }

        private void sessionsToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ShowExportToFileDialog(this.sessionsListView, "sessions");
        }

        private void settingsToolStripMenuItem_Click(object sender, EventArgs e) {
            this.settingsForm.ShowDialog();
        }

        private void receivePcapOverIPToolStripMenuItem_Click(object sender, EventArgs e) {
            this.pcapOverIpReceiverFactory.GetPcapOverIp(this.packetHandlerWrapper.PacketHandler, new AddCaseFileCallback(this.AddPcapFileToCasePanel), new PcapFileReader.CaseFileLoadedCallback(this.caseFileLoaded), new RunWorkerCompletedEventHandler(UpdateGuiControlsAfterParsingCompleteEventHandler), this);
        }

        private void getUpgradeCodeToolStripMenuItem_Click(object sender, EventArgs e) {
            this.upgradeCodeForm.ShowDialog(this);
        }

        private void signWithLicenseToolStripMenuItem_Click(object sender, EventArgs e) {
            this.licenseSignatureForm.ShowDialog(this);
        }

        private void changeCleartextDictionaryButton_Click_1(object sender, EventArgs e) {
            if (this.openTextFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK) {
                this.loadCleartextDictionary(this.openTextFileDialog.FileName, this.GuiProperties.UseCleartextTab);
            }
        }

        private void downloadRIPEDBToolStripMenuItem_Click(object sender, EventArgs e) {
            this.hostDetailsGenerator.DownloadDatabase();
        }

        private void credentialsSettingsCheckBox_Click(object sender, EventArgs e) {
            //we need to reload all credentials
            this.credentialsListView.BeginUpdate();
            this.credentialsListView.Items.Clear();
            List<PacketParser.NetworkCredential> credentials = new List<PacketParser.NetworkCredential>();
            foreach (PacketParser.NetworkCredential credential in this.PacketHandlerWrapper.PacketHandler.GetCredentials()) {
                if (credential.Password != null)
                    credentials.Add(credential);
                
            }
            this.AddCredentialsToCredentialList(credentials, false);
            this.controlTextDictionary[this.tabPageCredentials] = "Credentials (" + credentialsListView.Items.Count + ")";
            //this.SetControlText(this.tabPageCredentials, "Credentials (" + credentialsListView.Items.Count + ")");
            this.credentialsListView.EndUpdate();
        }

        private void clearGUIToolStripMenuItem_Click(object sender, EventArgs e) {
            this.ResetCapturedData(false, true);
        }

        private void keywordTextBox_KeyDown(object sender, KeyEventArgs e) {
            if (e.KeyCode == Keys.Enter || e.KeyCode == Keys.Return) {
                this.addKeyword(sender, e);
            }
        }

        private void addKeywordsFromFileButton_Click(object sender, EventArgs e) {
            if (this.openTextFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK) {
                if (this.openTextFileDialog.FileName != null && System.IO.File.Exists(this.openTextFileDialog.FileName)) {
                    List<string> lines = new List<string>();
                    using (System.IO.TextReader reader = System.IO.File.OpenText(this.openTextFileDialog.FileName)) {

                        while (true) {
                            string line = reader.ReadLine();
                            if (line == null)
                                break;//EOF
                            else
                                lines.Add(line);
                        }
                        reader.Close();
                    }
                    this.keywordListBox.BeginUpdate();
                    foreach (string line in lines) {
                        string errorMessage;

                        this.TryAddKeywordToListBox(line, out errorMessage);
                    }
                    this.keywordListBox.EndUpdate();
                    packetHandlerWrapper.UpdateKeywords((System.Collections.IEnumerable)this.keywordListBox.Items);
                    //this.packetHandlerWrapper.UpdateKeywords(lines);

                }
            }
        }

        private void showMetadataToolStripMenuItem_Click(object sender, EventArgs e) {
            if (casePanelFileListView.SelectedItems.Count > 0) {
                CaseFile caseFile = (CaseFile)casePanelFileListView.SelectedItems[0].Tag;
                //string filePath=caseFile.FilePathAndName;//.Text;
                CaseFileForm caseFileForm = new CaseFileForm(caseFile);
                caseFileForm.Show();
            }
        }

        
        private void ListView_DragDropOnItemDrag(object sender, ItemDragEventArgs e) {
            if(e.Item is ListViewItem listViewItem) {
                
                if (listViewItem?.Tag != null) {
                    string filePath;
                    if (listViewItem.Tag is PacketParser.FileTransfer.ReconstructedFile reconstructedFile)
                        filePath = reconstructedFile.FilePath;
                    else if (listViewItem.Tag is CaseFile caseFile)
                        filePath = caseFile.FilePathAndName;
                    else
                        filePath = listViewItem.Tag.ToString();
                    if (System.IO.File.Exists(filePath)) {
                        SharedUtils.Logger.Log(listViewItem.ListView.Name + " Drag-and-Drop: " + filePath, SharedUtils.Logger.EventLogEntryType.Information);
                        try {
                            DataObject dataObject = new DataObject(DataFormats.FileDrop, new string[] { filePath });
                            string uri = new System.Uri(filePath).AbsoluteUri;//useful when drag-and-dropping to browsers and other applications
                            dataObject.SetData(DataFormats.Text, uri);//makes drag-and-drop work in Linux without crashes when a text-drop is assumed
                            listViewItem.ListView.DoDragDrop(dataObject, DragDropEffects.Copy);
                        }
                        catch (Exception ex) {//Pokemon exception mode: catch 'em all
                            SharedUtils.Logger.Log("Error on DoDragDrop of " + filePath, SharedUtils.Logger.EventLogEntryType.Warning);
                            SharedUtils.Logger.Log(ex.GetType().ToString() + " : " + ex.StackTrace, SharedUtils.Logger.EventLogEntryType.Information);
                        }
                    }
                }
            }
        }

        


        private void messageEncodingComboBox_SelectedIndexChanged(object sender, EventArgs e) {
            if (this.messageEncodingComboBox.SelectedItem is EncodingWrapper && this.messageTextBox.Tag != null && this.messageTextBox.Tag is byte[]) {
                this.SetTextBoxText(this.messageTextBox, (byte[])this.messageTextBox.Tag, (this.messageEncodingComboBox.SelectedItem as EncodingWrapper).Encoding);
            }
        }

        private void removeSelectedFilesAndReloadCaseFilesToolStripMenuItem_Click(object sender, EventArgs e) {
            this.removeCaseFileMenuItem_Click(sender, e);
            this.reloadCaseFilesButton_Click(sender, e);
        }

        [Obsolete("Use ListView_DragDropOnItemDrag instead", true)]
        private void messageAttachmentListView_MouseDown(object sender, MouseEventArgs e) {
            //we don't wanna do drag-and-drop on double clicks
            if (e.Clicks == 1 && e.Button == System.Windows.Forms.MouseButtons.Left) {
                ListViewItem fileItem = this.messageAttachmentListView.GetItemAt(e.X, e.Y);
                if (fileItem != null && fileItem.Tag != null) {
                    string filePath = fileItem.Tag.ToString();
                    if (System.IO.File.Exists(filePath)) {
                        SharedUtils.Logger.Log("Drag-and-Drop: " + filePath, SharedUtils.Logger.EventLogEntryType.Information);
                        DataObject data = new DataObject(DataFormats.FileDrop, new string[] { filePath });
                        //this.DoDragDrop(data, DragDropEffects.Move);
                        try {
                            this.DoDragDrop(data, DragDropEffects.Copy);
                        }
                        catch {//Pokemon exception mode: catch 'em all
                            SharedUtils.Logger.Log("Error on DoDragDrop of " + filePath, SharedUtils.Logger.EventLogEntryType.Warning);
                        }
                    }
                }
                //networkHostTreeView.SelectedNode = networkHostTreeView.GetNodeAt(e.X, e.Y);
            }
        }

        private void readFromPacketCacheToolStripMenuItem_Click(object sender, EventArgs e) {
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.FileName = "powershell.exe";
            //startInfo.Arguments = "-WindowStyle Hidden -NonInteractive -NoProfile -Command echo hello; start-sleep -s 2; dir env:; start-sleep -s 3";
            string packetCachePcapFile = System.IO.Path.GetTempPath() + "PacketCache_NamedPipe_" + DateTime.Now.Ticks / 10000000 + ".pcap";
            SharedUtils.Logger.Log("Dumping PacketCache to " + packetCachePcapFile, SharedUtils.Logger.EventLogEntryType.Information);
            //To run PowerShell scripts: Set-ExecutionPolicy RemoteSigned
            //To disable PowerShell scripts (default): Set-ExecutionPolicy Restricted
            //this built-in script should run anyway.

            //$file = [System.IO.File]::OpenWrite('" + packetCachePcapFile + @"');
            startInfo.Arguments = @"-NonInteractive -NoProfile -Command $pipeStream = new-object System.IO.Pipes.NamedPipeClientStream '.','PacketCache','In';
$file = New-Object IO.FileStream '" + packetCachePcapFile + @"' ,'OpenOrCreate','Write','ReadWrite';
try {
    $pipeStream.Connect(1000);
    $buffer = new-object byte[] 4096;
    $n = $pipeStream.Read($buffer, 0, $buffer.Length);
    while ($n -gt 0) {
        $file.Write($buffer, 0, $n);
        $n = $pipeStream.Read($buffer, 0, $buffer.Length);
    }
}
finally {
    $file.Close();
    $pipeStream.Dispose();
}";

            //startInfo.Arguments = @"-NoProfile -Command while(1) {'loop'; start-sleep -s 1;}";
            //startInfo.RedirectStandardOutput = true;
            //startInfo.RedirectStandardError = true;
            //startInfo.UseShellExecute = false;
            startInfo.UseShellExecute = true;
            //startInfo.CreateNoWindow = false;
            startInfo.CreateNoWindow = true;
            startInfo.Verb = "runas";
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.ErrorDialog = true;

            BackgroundWorker backgroundPacketCacheReader = new BackgroundWorker();
            backgroundPacketCacheReader.DoWork += (s2, e2) => runProcessAndMonitorFileSize(e2, startInfo, packetCachePcapFile);
            backgroundPacketCacheReader.RunWorkerAsync();
        }


        private void runProcessAndMonitorFileSize(DoWorkEventArgs e, System.Diagnostics.ProcessStartInfo startInfo, string packetCachePcapFile) {
            try {
                using (System.Diagnostics.Process process = new System.Diagnostics.Process()) {
                    process.StartInfo = startInfo;
                    process.Start();

                    TimeSpan timeout = new TimeSpan(0, 0, 5);
                    DateTime lastFileSizeUpdate = DateTime.Now;

                    long bytesRead = 0;
                    bool loadPcapFileInvoked = false;
                    while (!process.WaitForExit(200)) {

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
                                    this.Invoke((MethodInvoker)delegate () { this.LoadPcapFile(packetCachePcapFile, true, System.IO.FileShare.ReadWrite); });
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
                        this.Invoke((MethodInvoker)delegate () { this.LoadPcapFile(packetCachePcapFile, true, System.IO.FileShare.ReadWrite); });
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

        private void imagesListView_MouseDoubleClick(object sender, MouseEventArgs e) {
            this.OpenImage_Click(sender, e);
        }


        private void expandAllToolStripMenuItem_Click(object sender, EventArgs e) {
            this.networkHostTreeView.ExpandAll();
        }

        private void collapseAllToolStripMenuItem_Click(object sender, EventArgs e) {
            this.networkHostTreeView.CollapseAll();
        }

        private void expandAllToolStripMenuItem1_Click(object sender, EventArgs e) {
            this.httpTransactionTreeView.ExpandAll();
        }

        private void collapseAllToolStripMenuItem1_Click(object sender, EventArgs e) {
            this.httpTransactionTreeView.CollapseAll();
        }

        private void httpTransactionShowAdsCheckBox_CheckedChanged(object sender, EventArgs e) {
            this.collapseAllToolStripMenuItem1_Click(sender, e);
        }

        private void httpTransactionTreeView_AfterSelect(object sender, TreeViewEventArgs e) {
            if (this.httpTransactionTreeNodeHandler != null && e.Node != null)
                this.httpTransactionTreeNodeHandler.ShowTransactionProperties(e.Node, this.httpTransactionPropertyGrid);

            lock (this.browsersMenuStrip) {
                foreach (var item in this.browsersMenuStripExtraItems)
                    this.browsersMenuStrip.Items.Remove(item);
                this.browsersMenuStripExtraItems.Clear();
                Tuple<System.Net.IPAddress, DateTime> ipAndDate = this.httpTransactionTreeNodeHandler.GetServerIp(e.Node);
                if (ipAndDate?.Item1 != null)
                    this.browsersMenuStripExtraItems.Add(this.GetIpLookupToolStripMenuItem(ipAndDate.Item1, ipAndDate.Item2));
                string hostname = this.httpTransactionTreeNodeHandler.GetServerHostname(e.Node);
                if (!string.IsNullOrEmpty(hostname))
                    this.browsersMenuStripExtraItems.Add(this.GetDomainLookupToolStripMenuItem(hostname));
                string url = this.httpTransactionTreeNodeHandler.GetUrl(e.Node);
                if (!string.IsNullOrEmpty(url))
                    this.browsersMenuStripExtraItems.Add(this.GetUrlLookupToolStripMenuItem(url));
                this.browsersMenuStrip.Items.AddRange(this.browsersMenuStripExtraItems.ToArray());

            }
        }

        private void setAdvertismentColorToolStripMenuItem_Click(object sender, EventArgs e) {
            if (this.httpTransactionTreeNodeHandler == null) {
                MessageBox.Show("Ad detection is only available in NetworkMiner Professional", "NetworkMiner Pro Required");
            }
            else {
                if (this.colorDialog1.ShowDialog() == DialogResult.OK) {
                    this._guiProperties.AdvertisementColor = this.colorDialog1.Color;
                    //this.httpTransactionTreeNodeHandler
                    this.httpTransactionTreeView.CollapseAll();//so that nodes will have to be re-colored on expand
                }
            }
        }

        private void ImagesListView_MouseWheel(object sender, System.Windows.Forms.MouseEventArgs e) {
            if (System.Windows.Forms.Control.ModifierKeys == Keys.Control)
                this.imageZoom(Math.Pow(1.2, 120.0 / e.Delta));
        }

        private void findHttpTransactionButton_Click(object sender, EventArgs e) {
            this.httpTransactionTreeNodeHandler.ShowTransactionProperties(null, this.httpTransactionPropertyGrid);
            Queue<TreeNode> queuedNodes = new Queue<TreeNode>();

            TreeNode nextMatch = null;
            TreeNode startNode = this.httpTransactionTreeView.SelectedNode;
            bool startNodePassed = false;
            if (startNode == null)
                startNodePassed = true;
            this.httpTransactionTreeView.ExpandAll();
            foreach (TreeNode node in this.httpTransactionTreeView.Nodes) {
                nextMatch = this.GetNextMatchingNode(startNode, node, queuedNodes, ref startNodePassed);
                if (nextMatch != null) {
                    this.httpTransactionTreeView.SelectedNode = nextMatch;
                    this.httpTransactionTreeView.Focus();
                    break;
                }
            }
            if (nextMatch == null) {
                foreach (TreeNode node in queuedNodes) {
                    if (this.httpTransactionTreeNodeHandler.Matches(node, this.findHttpTransactionTextBox.Text, this.findHttpTransactionCaseSensitiveCheckBox.Checked)) {
                        this.httpTransactionTreeView.SelectedNode = node;
                        this.httpTransactionTreeView.Focus();
                        break;
                    }
                }
            }
        }

        private TreeNode GetNextMatchingNode(TreeNode startNode, TreeNode nextNode, Queue<TreeNode> queuedNodes, ref bool startNodePassed) {

            if (startNodePassed) {
                //the first match we find from now on is the next match
                if (this.httpTransactionTreeNodeHandler.Matches(nextNode, this.findHttpTransactionTextBox.Text, this.findHttpTransactionCaseSensitiveCheckBox.Checked))
                    return nextNode;
            }
            else
                queuedNodes.Enqueue(nextNode);
            if (nextNode == startNode)//we've wrapped. nothing more to see
                startNodePassed = true;

            foreach (TreeNode childNode in nextNode.Nodes) {
                TreeNode nextMatch = GetNextMatchingNode(startNode, childNode, queuedNodes, ref startNodePassed);
                if (nextMatch != null)
                    return nextMatch;

            }
            return null;
        }

        private void findHttpTransactionTextBox_KeyDown(object sender, KeyEventArgs e) {
            if (e.KeyCode == Keys.Enter) {
                this.findHttpTransactionButton_Click(sender, e);
                this.findHttpTransactionTextBox.Focus();
            }
        }

        private void httpTransactionTreeView_KeyDown(object sender, KeyEventArgs e) {
            if (e.KeyCode == Keys.F3 && this.findHttpTransactionTextBox.Text != null && this.findHttpTransactionTextBox.Text.Length > 0)
                this.findHttpTransactionButton_Click(sender, e);

        }

        private void findNextToolStripMenuItem_Click(object sender, EventArgs e) {
            if (this.findHttpTransactionTextBox.Text != null && this.findHttpTransactionTextBox.Text.Length > 0)
                this.findHttpTransactionButton_Click(sender, e);
        }

        private void setInternetTrackerColorToolStripMenuItem_Click(object sender, EventArgs e) {
            if (this.httpTransactionTreeNodeHandler == null) {
                MessageBox.Show("Internet tracker detection is only available in NetworkMiner Professional", "NetworkMiner Pro Required");
            }
            else {
                if (this.colorDialog1.ShowDialog() == DialogResult.OK) {
                    this._guiProperties.InternetTrackerColor = this.colorDialog1.Color;
                    //this.httpTransactionTreeNodeHandler
                    this.httpTransactionTreeView.CollapseAll();//so that nodes will have to be re-colored on expand
                }
            }
        }

        private void ShowFileDetails(object sender, EventArgs e) {
            ListViewItem item = null;

            if (sender is ListViewItem senderItem) {
                item = senderItem;
            }
            else if (sender == this.filesListView && this.filesListView.SelectedItems.Count > 0) {
                item = this.filesListView.SelectedItems[0];
            }
            else if (sender != null && sender is ToolStripMenuItem tsmi && tsmi.GetCurrentParent() == this.filesListView.ContextMenuStrip && this.filesListView.SelectedItems.Count > 0) {
                item = this.filesListView.SelectedItems[0];
            }
            if (item != null) {
                ListView.ColumnHeaderCollection columns = item.ListView.Columns;
                //ColumnHeader x = columns[this.sourceHostHeader.Index];
                string sourceHost = item.SubItems[this.sourceHostHeader.Index].Text;
                string destinationHost = item.SubItems[this.destinationHostHeader.Index].Text;
                List<(string, string)> items = new List<(string, string)>();
                for (int i = 0; i < item.SubItems.Count; i++) {
                    if (item.SubItems[i] != null) {
                        ListViewItem.ListViewSubItem subItem = item.SubItems[i];
                        items.Add((columns[i]?.Text, subItem.Text));
                    }
                }
                string filePath = this.filesListView.SelectedItems[0].Tag.ToString();//.Text;
                if (System.IO.File.Exists(filePath)) {
                    try {
                        ExtractedFileDetailsForm fileDetailsForm = new ExtractedFileDetailsForm(filePath);
                        fileDetailsForm.FileDetails.Source = sourceHost;
                        fileDetailsForm.FileDetails.Destination = destinationHost;
                        fileDetailsForm.Show(this);
                    }
                    catch (System.IO.IOException ioException) {
                        MessageBox.Show(ioException.Message, "Unable to Read File Details");
                    }
                }
            }
        }
        

        private void selectParentNodeToolStripMenuItem_Click(object sender, EventArgs e) {
            TreeNode currentNode = this.httpTransactionTreeView.SelectedNode;
            if (currentNode != null && currentNode.Parent != null)
                this.httpTransactionTreeView.SelectedNode = currentNode.Parent;
            
        }

        private void collapseAllButThisToolStripMenuItem_Click(object sender, EventArgs e) {
            TreeNode currentNode = this.httpTransactionTreeView.SelectedNode;
            if (currentNode == null)
                MessageBox.Show("Please select a node first!");
            else {
                //this.httpTransactionTreeView.CollapseAll();
                System.Collections.Generic.HashSet<TreeNode> keepers = new HashSet<TreeNode>();
                TreeNode parent = currentNode.Parent;
                while (parent != null) {
                    keepers.Add(parent);
                    parent = parent.Parent;
                }

                List<TreeNode> allNodes = new List<TreeNode>();
                foreach (TreeNode n in this.httpTransactionTreeView.Nodes) {
                    allNodes.Add(n);
                    allNodes.AddRange(n.GetOpenChildTreeNodes());
                }
                foreach (TreeNode n in allNodes)
                    if (!keepers.Contains(n) && n.IsExpanded)
                        n.Collapse();
                //this.httpTransactionTreeView.SelectedNode = currentNode;
            }
        }

        private void checkForUpdatesToolStripMenuItem_Click(object sender, EventArgs e) {
            //this will check for the current .NET version for some reason?!
            //System.Reflection.Assembly.GetCallingAssembly().GetName().Version
            SharedUtils.Logger.Log("Manually checking for updates...", SharedUtils.Logger.EventLogEntryType.Information);
            NetworkMiner.UpdateCheck.ShowNewVersionFormIfAvailableAsync(this, System.Reflection.Assembly.GetEntryAssembly().GetName().Version, true);

        }

        private void keywordListBox_KeyDown(object sender, KeyEventArgs e) {
            if (e.KeyCode == Keys.Delete) {
                e.SuppressKeyPress = true;
                this.removeKeywordButton_Click(sender, e);
            }
        }

        private void voipDataGridView_CellContentClick(object sender, DataGridViewCellEventArgs e) {
            if (sender is DataGridView senderGrid) {
                if (e.RowIndex >= 0) {
                    if (senderGrid == this.voipDataGridView) {
                        if (this.voipDataGridView.Rows[e.RowIndex] is VoipCall.VoipCallDataGridViewRow voipRow) {
                            if (e.ColumnIndex == this.VoipPlayColumn.Index)
                                try {
                                    voipRow.Play();
                                }
                                catch (Exception ex) {
                                    MessageBox.Show(ex.Message, "Error Playing VoIP Call");
                                    SharedUtils.Logger.Log(ex.GetType().ToString() + " : " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                                }
                            else if (e.ColumnIndex == this.VoipStopColumn.Index)
                                voipRow.Stop();
                            else if (e.ColumnIndex == this.VoipSaveWavColumn.Index) {
                                if (System.IO.File.Exists(voipRow.VoipCall.WavFilePath)) {
                                    SaveFileDialog saveWavDialog = new SaveFileDialog();
                                    System.IO.FileInfo fi = new System.IO.FileInfo(voipRow.VoipCall.WavFilePath);
                                    saveWavDialog.FileName = fi.Name;
                                    saveWavDialog.Filter = "WAVE|*.wav";
                                    saveWavDialog.Title = "Save VoIP .WAV File As...";
                                    if (saveWavDialog.ShowDialog() == DialogResult.OK) {
                                        System.IO.File.Copy(voipRow.VoipCall.WavFilePath, saveWavDialog.FileName);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private void voipDataGridView_KeyDown(object sender, KeyEventArgs e) {
            if(e.KeyCode == Keys.Space && this.voipDataGridView.SelectedRows.Count > 0) {
                if (this.voipDataGridView.SelectedRows[0] is VoipCall.VoipCallDataGridViewRow voipRow)
                    voipRow.Play();
             }
            //e.Handled = true;
        }

        [Obsolete("Use ListView_DragDropOnItemDrag instead", true)]
        private void casePanelFileListView_ItemDrag(object sender, ItemDragEventArgs e) {
            if (e.Item is ListViewItem fileItem) {
                if (fileItem != null && fileItem.Tag != null && fileItem.Tag is CaseFile caseFile) {

                    //string filePath = fileItem.Tag.ToString();
                    if (System.IO.File.Exists(caseFile.FilePathAndName)) {
                        DataObject data = new DataObject(DataFormats.FileDrop, new string[] { caseFile.FilePathAndName });
                        SharedUtils.Logger.Log("Drag-and-Drop: " + caseFile.FilePathAndName, SharedUtils.Logger.EventLogEntryType.Information);
                        try {
                            this.DoDragDrop(data, DragDropEffects.Copy);
                        }
                        catch {//Pokemon exception mode: catch 'em all
                            SharedUtils.Logger.Log("Error on DoDragDrop of " + caseFile.FilePathAndName, SharedUtils.Logger.EventLogEntryType.Warning);
                        }
                    }
                }
            }
        }

        private void httpTransactionTreeView_NodeMouseClick(object sender, TreeNodeMouseClickEventArgs e) {
            e.Node.TreeView.SelectedNode = e.Node;
        }

        private void submitParameterToCyberChefToolStripMenuItem_Click(object sender, EventArgs e) {
            if (this.parametersListView.SelectedItems.Count > 0) {
                System.Collections.Generic.KeyValuePair<string, string> nameValueTag = (System.Collections.Generic.KeyValuePair<string, string>)this.parametersListView.SelectedItems[0].Tag;
                string b64 = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(nameValueTag.Value));
                string query = System.Web.HttpUtility.UrlEncode(b64.TrimEnd('='));
                SharedUtils.SystemHelper.ProcessStart("https://gchq.github.io/CyberChef/#input=" + query);
            }
            
        }

        /*
        private void filesListView_DoubleClick(object sender, EventArgs e) {
            this.ShowFileDetails(sender, e);
        }
        */

        private void filesListView_SelectedIndexChanged(object sender, EventArgs e) {
            lock (this.filesListView.ContextMenuStrip) {
                foreach (var item in this.filesMenuStripExtraItems)
                    this.filesListView.ContextMenuStrip.Items.Remove(item);
                this.filesMenuStripExtraItems.Clear();
                if (this.filesListView.SelectedItems.Count > 0) {
                    string filePath = this.filesListView.SelectedItems[0].Tag.ToString();//.Text;
                    if (System.IO.File.Exists(filePath)) {
                        this.filesMenuStripExtraItems.Add(this.GetHashLookupToolStripMenuItem(filePath));
                        this.filesMenuStripExtraItems.Add(this.GetSubmitFileToolStripMenuItem(filePath));
                        
                    }
                }
                if (this.filesMenuStripExtraItems.Count > 0)
                    this.filesMenuStripExtraItems.Insert(0, new ToolStripSeparator());
                this.filesListView.ContextMenuStrip.Items.AddRange(filesMenuStripExtraItems.ToArray());
            }
        }

        private void hostMenuStrip_Closing(object sender, ToolStripDropDownClosingEventArgs e) {
            lock (this.hostMenuStrip) {
                foreach(var item in this.hostMenuStripExtraItems)
                    this.hostMenuStrip.Items.Remove(item);
            }
        }
    }
}