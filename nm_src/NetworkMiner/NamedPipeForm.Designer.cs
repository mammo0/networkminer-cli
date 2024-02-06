namespace NetworkMiner {
    partial class NamedPipeForm {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(NamedPipeForm));
            this.namedPipeSettingsPropertyGrid = new System.Windows.Forms.PropertyGrid();
            this.startReadNamedPipeButton = new System.Windows.Forms.Button();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.bytesReadLabel = new System.Windows.Forms.ToolStripStatusLabel();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.statusStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // namedPipeSettingsPropertyGrid
            // 
            this.namedPipeSettingsPropertyGrid.Dock = System.Windows.Forms.DockStyle.Fill;
            this.namedPipeSettingsPropertyGrid.Location = new System.Drawing.Point(0, 0);
            this.namedPipeSettingsPropertyGrid.Name = "namedPipeSettingsPropertyGrid";
            this.namedPipeSettingsPropertyGrid.PropertySort = System.Windows.Forms.PropertySort.NoSort;
            this.namedPipeSettingsPropertyGrid.Size = new System.Drawing.Size(411, 162);
            this.namedPipeSettingsPropertyGrid.TabIndex = 0;
            this.namedPipeSettingsPropertyGrid.ToolbarVisible = false;
            // 
            // startReadNamedPipeButton
            // 
            this.startReadNamedPipeButton.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.startReadNamedPipeButton.Location = new System.Drawing.Point(0, 162);
            this.startReadNamedPipeButton.Name = "startReadNamedPipeButton";
            this.startReadNamedPipeButton.Size = new System.Drawing.Size(411, 23);
            this.startReadNamedPipeButton.TabIndex = 1;
            this.startReadNamedPipeButton.Text = "Start";
            this.startReadNamedPipeButton.UseVisualStyleBackColor = true;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.bytesReadLabel});
            this.statusStrip1.Location = new System.Drawing.Point(0, 185);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(411, 22);
            this.statusStrip1.TabIndex = 2;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // bytesReadLabel
            // 
            this.bytesReadLabel.Name = "bytesReadLabel";
            this.bytesReadLabel.Size = new System.Drawing.Size(73, 17);
            this.bytesReadLabel.Text = "Bytes read: 0";
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // NamedPipeForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(411, 207);
            this.Controls.Add(this.namedPipeSettingsPropertyGrid);
            this.Controls.Add(this.startReadNamedPipeButton);
            this.Controls.Add(this.statusStrip1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "NamedPipeForm";
            this.Text = "Read PCAP From Named Pipe";
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.PropertyGrid namedPipeSettingsPropertyGrid;
        private System.Windows.Forms.Button startReadNamedPipeButton;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel bytesReadLabel;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
    }
}