namespace NetworkMiner {
    partial class UpdateCheck {
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(UpdateCheck));
            this.releaseNoteLinkLabel = new System.Windows.Forms.LinkLabel();
            this.newVersionTextBox = new System.Windows.Forms.TextBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.panel2 = new System.Windows.Forms.Panel();
            this.downloadButton = new System.Windows.Forms.Button();
            this.panel1.SuspendLayout();
            this.panel2.SuspendLayout();
            this.SuspendLayout();
            // 
            // releaseNoteLinkLabel
            // 
            this.releaseNoteLinkLabel.AutoSize = true;
            this.releaseNoteLinkLabel.Dock = System.Windows.Forms.DockStyle.Right;
            this.releaseNoteLinkLabel.Location = new System.Drawing.Point(341, 0);
            this.releaseNoteLinkLabel.Margin = new System.Windows.Forms.Padding(3);
            this.releaseNoteLinkLabel.Name = "releaseNoteLinkLabel";
            this.releaseNoteLinkLabel.Padding = new System.Windows.Forms.Padding(3, 7, 3, 3);
            this.releaseNoteLinkLabel.Size = new System.Drawing.Size(107, 23);
            this.releaseNoteLinkLabel.TabIndex = 1;
            this.releaseNoteLinkLabel.TabStop = true;
            this.releaseNoteLinkLabel.Text = "Open Release Note";
            this.releaseNoteLinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkClicked);
            // 
            // newVersionTextBox
            // 
            this.newVersionTextBox.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.newVersionTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.newVersionTextBox.Location = new System.Drawing.Point(5, 5);
            this.newVersionTextBox.Multiline = true;
            this.newVersionTextBox.Name = "newVersionTextBox";
            this.newVersionTextBox.ReadOnly = true;
            this.newVersionTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.newVersionTextBox.Size = new System.Drawing.Size(448, 126);
            this.newVersionTextBox.TabIndex = 3;
            this.newVersionTextBox.Text = "There is a newer version of NetworkMiner available. Please update to version 1.2." +
    "3.";
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.newVersionTextBox);
            this.panel1.Controls.Add(this.panel2);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.panel1.Location = new System.Drawing.Point(0, 0);
            this.panel1.Name = "panel1";
            this.panel1.Padding = new System.Windows.Forms.Padding(5);
            this.panel1.Size = new System.Drawing.Size(458, 164);
            this.panel1.TabIndex = 4;
            // 
            // panel2
            // 
            this.panel2.Controls.Add(this.downloadButton);
            this.panel2.Controls.Add(this.releaseNoteLinkLabel);
            this.panel2.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.panel2.Location = new System.Drawing.Point(5, 131);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(448, 28);
            this.panel2.TabIndex = 1;
            // 
            // downloadButton
            // 
            this.downloadButton.Dock = System.Windows.Forms.DockStyle.Left;
            this.downloadButton.Enabled = false;
            this.downloadButton.Location = new System.Drawing.Point(0, 0);
            this.downloadButton.Name = "downloadButton";
            this.downloadButton.Size = new System.Drawing.Size(75, 28);
            this.downloadButton.TabIndex = 0;
            this.downloadButton.Text = "Download";
            this.downloadButton.UseVisualStyleBackColor = true;
            this.downloadButton.Click += new System.EventHandler(this.downloadButton_Click);
            // 
            // UpdateCheck
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(458, 164);
            this.Controls.Add(this.panel1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "UpdateCheck";
            this.Text = "Update";
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.panel2.ResumeLayout(false);
            this.panel2.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.LinkLabel releaseNoteLinkLabel;
        private System.Windows.Forms.TextBox newVersionTextBox;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.Button downloadButton;
        private System.Windows.Forms.Panel panel2;
    }
}