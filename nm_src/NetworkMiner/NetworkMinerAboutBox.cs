using System;

using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using System.Reflection;
using System.Text;

namespace NetworkMiner {
     public partial class NetworkMinerAboutBox : Form {

        public enum AboutTabs {
            NetworkMiner,
            Credits,
            Protocols,
            //License,
            EULA
        }

        private Assembly exeAssembly;

        public NetworkMinerAboutBox(string link, System.Collections.Specialized.NameValueCollection parentFormAboutTextNVC) {

            InitializeComponent();
            this.exeAssembly = Assembly.GetEntryAssembly();

            System.Collections.Specialized.NameValueCollection localAboutTextNVC = new System.Collections.Specialized.NameValueCollection(parentFormAboutTextNVC);

            //  Initialize the AboutBox to display the product information from the assembly information.
            //  Change assembly information settings for your application through either:
            //  - Project->Properties->Application->Assembly Information
            //  - AssemblyInfo.cs
            this.Text = String.Format("About {0}", AssemblyTitle);
            this.labelProductName.Text = AssemblyProduct;
            this.labelVersion.Text = String.Format("Version {0}", AssemblyVersion);
            this.labelCopyright.Text = AssemblyCopyright;
            this.linkLabelHomepage.Text = link;
            this.linkLabelHomepage.Links.Add(0, link.Length, link);
            this.linkLabelHomepage.LinkClicked+=new LinkLabelLinkClickedEventHandler(linkLabelHomepage_Click);

            if(localAboutTextNVC.Count == 0) {
                StringBuilder nmText = new StringBuilder();
                nmText.AppendLine("NetworkMiner is an open source Network Forensic Analysis Tool (NFAT) with a built-in passive network sniffer/packet capturing tool. It can detect OS's, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis.");
                nmText.AppendLine();
                nmText.AppendLine("Author: Erik Hjelmvik, <erik.hjelmvik [at] gmail.com>");
                nmText.AppendLine();
                nmText.AppendLine("Website: https://www.netresec.com/");
                nmText.AppendLine();
                nmText.AppendLine("NetworkMiner is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License.");
                localAboutTextNVC.Add(nameof(AboutTabs.NetworkMiner), nmText.ToString());
            }

            StringBuilder creditBuilder = new StringBuilder();
            creditBuilder.AppendLine("NetworkMiner uses OS fingerprinting databases from Satori, created and maintained by Eric Kollmann. Satori can be downloaded from https://github.com/xnih/satori/");
            creditBuilder.AppendLine();
            creditBuilder.AppendLine("NetworkMiner uses the MAC address database mac-ages, created and maintained by HD Moore. Mac-ages is available at https://github.com/hdm/mac-ages");
            creditBuilder.AppendLine();
            creditBuilder.AppendLine("NetworkMiner uses the OS fingerprinting databse from p0f, created by Michal Zalewski <lcamtuf@coredump.cx>. P0f is available at http://lcamtuf.coredump.cx/p0f3/");
            if (localAboutTextNVC[nameof(AboutTabs.Credits)] == null)
                localAboutTextNVC.Add(nameof(AboutTabs.Credits), creditBuilder.ToString());
            else
                localAboutTextNVC[nameof(AboutTabs.Credits)] = localAboutTextNVC[nameof(AboutTabs.Credits)] + creditBuilder.ToString();

            StringBuilder protocolString = new System.Text.StringBuilder("Parsed application layer (L7) protocols include: ");
            foreach (PacketParser.ApplicationLayerProtocol l7proto in Enum.GetValues(typeof(PacketParser.ApplicationLayerProtocol))) {
                if (l7proto != PacketParser.ApplicationLayerProtocol.Unknown)
                    protocolString.Append(l7proto + ", ");
            }
            protocolString.Remove(protocolString.Length - 2, 2);
            localAboutTextNVC.Add(nameof(AboutTabs.Protocols), protocolString.ToString());
            

            if (localAboutTextNVC.Count > 0) {
                this.aboutTabControl.SuspendLayout();
                this.aboutTabControl.TabPages.Clear();
                foreach (string key in localAboutTextNVC.Keys) {
                    if (localAboutTextNVC[key]?.Length > 0) {
                        TabPage tp = new TabPage(key);
                        this.aboutTabControl.Controls.Add(tp);
                        tp.Controls.Add(new TextBox {
                            Text = localAboutTextNVC[key],
                            Dock = DockStyle.Fill,
                            Multiline = true,
                            ReadOnly = true,
                            ScrollBars = ScrollBars.Both
                        });
                    }
                }
                this.aboutTabControl.ResumeLayout();
            }
        }

        void linkLabelHomepage_Click(object sender, System.Windows.Forms.LinkLabelLinkClickedEventArgs e) {
            string target = e.Link.LinkData as string;
            //System.Diagnostics.Process.Start(target);
            SharedUtils.SystemHelper.ProcessStart(target);
        }

        #region Assembly Attribute Accessors

        public string AssemblyTitle {
            get {
                // Get all Title attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyTitleAttribute), false);
                // If there is at least one Title attribute
                if(attributes.Length > 0) {
                    // Select the first one
                    AssemblyTitleAttribute titleAttribute = (AssemblyTitleAttribute)attributes[0];
                    // If it is not an empty string, return it
                    if(titleAttribute.Title != "")
                        return titleAttribute.Title;
                }
                // If there was no Title attribute, or if the Title attribute was the empty string, return the .exe name
                return System.IO.Path.GetFileNameWithoutExtension(this.exeAssembly.CodeBase);
            }
        }

        public string AssemblyVersion {
            get {
                return this.exeAssembly.GetName().Version.ToString();
            }
        }

        public string AssemblyDescription {
            get {
                // Get all Description attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyDescriptionAttribute), false);
                // If there aren't any Description attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Description attribute, return its value
                return ((AssemblyDescriptionAttribute)attributes[0]).Description;
            }
        }

        public string AssemblyProduct {
            get {
                // Get all Product attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyProductAttribute), false);
                // If there aren't any Product attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Product attribute, return its value
                return ((AssemblyProductAttribute)attributes[0]).Product;
            }
        }

        public string AssemblyCopyright {
            get {
                // Get all Copyright attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyCopyrightAttribute), false);
                // If there aren't any Copyright attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Copyright attribute, return its value
                return ((AssemblyCopyrightAttribute)attributes[0]).Copyright;
            }
        }

        public string AssemblyCompany {
            get {
                // Get all Company attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyCompanyAttribute), false);
                // If there aren't any Company attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Company attribute, return its value
                return ((AssemblyCompanyAttribute)attributes[0]).Company;
            }
        }
        #endregion
    }
}
