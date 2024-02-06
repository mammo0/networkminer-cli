using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

using System.Reflection;
using System.Linq;

namespace NetworkMiner {

    public partial class ExtractedFileDetailsForm : Form {

        internal PropertyGridDetails FileDetails { get; }
        private uint maxBytesToRead = 1024;//preferably more than 256 in order to include a full PE header


        public int PropertyGridLabelWidth
        {
            get
            {
                FieldInfo fi = this.fileDetailsPropertyGrid.GetType().GetField("gridView", BindingFlags.Instance | BindingFlags.NonPublic);
                if (fi != null) {
                    Control view = fi.GetValue(fileDetailsPropertyGrid) as Control;
                    if (view != null) {
                        //protected int InternalLabelWidth
                        PropertyInfo propInfo = view.GetType().GetProperty("InternalLabelWidth", BindingFlags.NonPublic | BindingFlags.Instance);
                        return (int)propInfo.GetValue(view, new object[] { });
                    }
                }
                return 0;
            }
            set
            {
                FieldInfo fi = this.fileDetailsPropertyGrid.GetType().GetField("gridView", BindingFlags.Instance | BindingFlags.NonPublic);
                if (fi != null) {
                    Control view = fi.GetValue(this.fileDetailsPropertyGrid) as Control;
                    if (view != null) {
                        MethodInfo mi = view.GetType().GetMethod("MoveSplitterTo", BindingFlags.Instance | BindingFlags.NonPublic);
                        if (mi != null)
                            mi.Invoke(view, new object[] { value });
                    }
                }
            }
        }


        public ExtractedFileDetailsForm(string filePath) {
            this.InitializeComponent();
            this.FileDetails = new PropertyGridDetails(filePath);
            this.fileDetailsPropertyGrid.SelectedObject = this.FileDetails;
            this.Text = this.FileDetails.Name + " - File Details";
            this.bytesToReadTextBox.Text = this.maxBytesToRead.ToString();
            //this.UpdateHexTextBox();
        }

        private void UpdateHexTextBox() {
            lock (this.hexTextBox) {
                this.hexTextBox.Clear();
                if (this.maxBytesToRead > 0) {
                    byte[] buffer = new byte[this.maxBytesToRead];
                    int bytesRead;
                    using (System.IO.FileStream fileStream = new System.IO.FileStream(this.FileDetails.Path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, (int)this.maxBytesToRead, System.IO.FileOptions.SequentialScan)) {
                        bytesRead = fileStream.Read(buffer, 0, (int)this.maxBytesToRead);
                    }
                    if (buffer.Length > bytesRead)
                        buffer = buffer.Take(bytesRead).ToArray();
                    this.hexTextBox.Text = PacketParser.Utils.ByteConverter.ToXxdHexString(buffer, 16);
                    if(bytesRead >= 4 && this.identifiedFileTypeLabelValue.Text.Any(c => char.IsLower(c))) {
                        string extension = PacketParser.FileTransfer.FileStreamAssembler.GetExtensionFromHeader(buffer);
                        if(string.IsNullOrEmpty(extension)) {
                            this.identifiedFileTypeLabelText.Visible = false;
                            this.identifiedFileTypeLabelValue.Visible = false;
                        }
                        else {
                            this.identifiedFileTypeLabelText.Visible = true;
                            this.identifiedFileTypeLabelValue.Text = extension.ToUpper();
                            this.identifiedFileTypeLabelValue.Visible = true;
                        }
                    }
                }
            }
        }

        private void FileDetailsForm_VisibleChanged(object sender, EventArgs e) {

            if (this.Visible) {
                this.BeginInvoke((MethodInvoker)delegate () { this.PropertyGridLabelWidth = 168; });
            }

        }

        [Obfuscation(Feature = "Apply to member * when property and public: renaming", Exclude = true)]
        internal class PropertyGridDetails {
            private System.IO.FileInfo fileInfo;

            public string Name { get { return this.fileInfo.Name; } }
            public string MD5 { get; }
            public string SHA1 { get; }
            public string SHA256 { get; }
            public string Path { get; }
            public long Size { get { return this.fileInfo.Length; } }
            public DateTime LastWriteTime { get { return this.fileInfo.LastWriteTime; } }
            public string Source { get; internal set; }
            public string Destination { get; internal set; }

            internal PropertyGridDetails(string path) {
                this.Path = path;
                this.fileInfo = new System.IO.FileInfo(this.Path);
                this.MD5 = SharedUtils.Md5SingletonHelper.Instance.GetMd5Sum(this.Path);
                this.SHA1 = SharedUtils.Md5SingletonHelper.Instance.GetSha1Sum(this.Path);
                this.SHA256 = SharedUtils.Md5SingletonHelper.Instance.GetSha256Sum(this.Path);
            }
        }

        private void bytesToReadNumericUpDown_ValueChanged(object sender, EventArgs e) {
            this.UpdateHexTextBox();
        }

        private void numericUpDown1_ValueChanged(object sender, EventArgs e) {
            this.hexTextBox.Font = new Font(this.hexTextBox.Font.FontFamily, (float)this.fontSizeNumericUpDown.Value);
        }

        private void textBox1_TextChanged(object sender, EventArgs e) {
            if(string.IsNullOrEmpty(this.bytesToReadTextBox.Text))
                this.maxBytesToRead = 0;
            else if (UInt32.TryParse(this.bytesToReadTextBox.Text, out uint number)) {
                this.maxBytesToRead = number;
            }
            else
                this.bytesToReadTextBox.Text = this.maxBytesToRead.ToString();
            this.UpdateHexTextBox();
        }
    }



        
    
}
