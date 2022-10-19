namespace NetworkMiner {
    partial class ExtractedFileDetailsForm {
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ExtractedFileDetailsForm));
            this.fileDetailsPropertyGrid = new System.Windows.Forms.PropertyGrid();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.hexTextBox = new System.Windows.Forms.TextBox();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.flowLayoutPanel1 = new System.Windows.Forms.FlowLayoutPanel();
            this.label1 = new System.Windows.Forms.Label();
            this.bytesToReadTextBox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.fontSizeNumericUpDown = new System.Windows.Forms.NumericUpDown();
            this.identifiedFileTypeLabelText = new System.Windows.Forms.Label();
            this.identifiedFileTypeLabelValue = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.flowLayoutPanel1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.fontSizeNumericUpDown)).BeginInit();
            this.SuspendLayout();
            // 
            // fileDetailsPropertyGrid
            // 
            this.fileDetailsPropertyGrid.CommandsVisibleIfAvailable = false;
            this.fileDetailsPropertyGrid.Dock = System.Windows.Forms.DockStyle.Fill;
            this.fileDetailsPropertyGrid.HelpVisible = false;
            this.fileDetailsPropertyGrid.Location = new System.Drawing.Point(0, 0);
            this.fileDetailsPropertyGrid.Name = "fileDetailsPropertyGrid";
            this.fileDetailsPropertyGrid.PropertySort = System.Windows.Forms.PropertySort.NoSort;
            this.fileDetailsPropertyGrid.Size = new System.Drawing.Size(504, 162);
            this.fileDetailsPropertyGrid.TabIndex = 0;
            this.fileDetailsPropertyGrid.ToolbarVisible = false;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Location = new System.Drawing.Point(0, 369);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(504, 22);
            this.statusStrip1.TabIndex = 1;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // hexTextBox
            // 
            this.hexTextBox.AccessibleName = "Hex Window";
            this.hexTextBox.BackColor = System.Drawing.SystemColors.Window;
            this.hexTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.hexTextBox.Font = new System.Drawing.Font("Consolas", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hexTextBox.Location = new System.Drawing.Point(0, 26);
            this.hexTextBox.Multiline = true;
            this.hexTextBox.Name = "hexTextBox";
            this.hexTextBox.ReadOnly = true;
            this.hexTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.hexTextBox.Size = new System.Drawing.Size(504, 177);
            this.hexTextBox.TabIndex = 3;
            this.hexTextBox.WordWrap = false;
            // 
            // splitContainer1
            // 
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.FixedPanel = System.Windows.Forms.FixedPanel.Panel1;
            this.splitContainer1.Location = new System.Drawing.Point(0, 0);
            this.splitContainer1.Name = "splitContainer1";
            this.splitContainer1.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.fileDetailsPropertyGrid);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.hexTextBox);
            this.splitContainer1.Panel2.Controls.Add(this.flowLayoutPanel1);
            this.splitContainer1.Size = new System.Drawing.Size(504, 369);
            this.splitContainer1.SplitterDistance = 162;
            this.splitContainer1.TabIndex = 4;
            // 
            // flowLayoutPanel1
            // 
            this.flowLayoutPanel1.AutoSize = true;
            this.flowLayoutPanel1.Controls.Add(this.label1);
            this.flowLayoutPanel1.Controls.Add(this.bytesToReadTextBox);
            this.flowLayoutPanel1.Controls.Add(this.label2);
            this.flowLayoutPanel1.Controls.Add(this.fontSizeNumericUpDown);
            this.flowLayoutPanel1.Controls.Add(this.identifiedFileTypeLabelText);
            this.flowLayoutPanel1.Controls.Add(this.identifiedFileTypeLabelValue);
            this.flowLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Top;
            this.flowLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            this.flowLayoutPanel1.Name = "flowLayoutPanel1";
            this.flowLayoutPanel1.Size = new System.Drawing.Size(504, 26);
            this.flowLayoutPanel1.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(3, 0);
            this.label1.Name = "label1";
            this.label1.Padding = new System.Windows.Forms.Padding(0, 6, 0, 0);
            this.label1.Size = new System.Drawing.Size(94, 19);
            this.label1.TabIndex = 1;
            this.label1.Text = "Max bytes to read:";
            // 
            // bytesToReadTextBox
            // 
            this.bytesToReadTextBox.Location = new System.Drawing.Point(103, 3);
            this.bytesToReadTextBox.MaxLength = 7;
            this.bytesToReadTextBox.Name = "bytesToReadTextBox";
            this.bytesToReadTextBox.Size = new System.Drawing.Size(63, 20);
            this.bytesToReadTextBox.TabIndex = 4;
            this.bytesToReadTextBox.TextChanged += new System.EventHandler(this.textBox1_TextChanged);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(172, 0);
            this.label2.Name = "label2";
            this.label2.Padding = new System.Windows.Forms.Padding(0, 6, 0, 0);
            this.label2.Size = new System.Drawing.Size(52, 19);
            this.label2.TabIndex = 2;
            this.label2.Text = "Font size:";
            // 
            // fontSizeNumericUpDown
            // 
            this.fontSizeNumericUpDown.Location = new System.Drawing.Point(230, 3);
            this.fontSizeNumericUpDown.Maximum = new decimal(new int[] {
            30,
            0,
            0,
            0});
            this.fontSizeNumericUpDown.Minimum = new decimal(new int[] {
            1,
            0,
            0,
            0});
            this.fontSizeNumericUpDown.Name = "fontSizeNumericUpDown";
            this.fontSizeNumericUpDown.Size = new System.Drawing.Size(45, 20);
            this.fontSizeNumericUpDown.TabIndex = 3;
            this.fontSizeNumericUpDown.Value = new decimal(new int[] {
            10,
            0,
            0,
            0});
            this.fontSizeNumericUpDown.ValueChanged += new System.EventHandler(this.numericUpDown1_ValueChanged);
            // 
            // identifiedFileTypeLabelText
            // 
            this.identifiedFileTypeLabelText.AutoSize = true;
            this.identifiedFileTypeLabelText.Location = new System.Drawing.Point(281, 0);
            this.identifiedFileTypeLabelText.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
            this.identifiedFileTypeLabelText.Name = "identifiedFileTypeLabelText";
            this.identifiedFileTypeLabelText.Padding = new System.Windows.Forms.Padding(0, 6, 0, 0);
            this.identifiedFileTypeLabelText.Size = new System.Drawing.Size(49, 19);
            this.identifiedFileTypeLabelText.TabIndex = 5;
            this.identifiedFileTypeLabelText.Text = "File type:";
            this.identifiedFileTypeLabelText.TextAlign = System.Drawing.ContentAlignment.TopRight;
            // 
            // identifiedFileTypeLabelValue
            // 
            this.identifiedFileTypeLabelValue.AutoSize = true;
            this.identifiedFileTypeLabelValue.Location = new System.Drawing.Point(330, 0);
            this.identifiedFileTypeLabelValue.Margin = new System.Windows.Forms.Padding(0, 0, 3, 0);
            this.identifiedFileTypeLabelValue.Name = "identifiedFileTypeLabelValue";
            this.identifiedFileTypeLabelValue.Padding = new System.Windows.Forms.Padding(0, 6, 0, 0);
            this.identifiedFileTypeLabelValue.Size = new System.Drawing.Size(37, 19);
            this.identifiedFileTypeLabelValue.TabIndex = 6;
            this.identifiedFileTypeLabelValue.Text = "(none)";
            // 
            // ExtractedFileDetailsForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(504, 391);
            this.Controls.Add(this.splitContainer1);
            this.Controls.Add(this.statusStrip1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "ExtractedFileDetailsForm";
            this.Text = "File Details";
            this.VisibleChanged += new System.EventHandler(this.FileDetailsForm_VisibleChanged);
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel2.ResumeLayout(false);
            this.splitContainer1.Panel2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.flowLayoutPanel1.ResumeLayout(false);
            this.flowLayoutPanel1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.fontSizeNumericUpDown)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.PropertyGrid fileDetailsPropertyGrid;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.TextBox hexTextBox;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.FlowLayoutPanel flowLayoutPanel1;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.NumericUpDown fontSizeNumericUpDown;
        private System.Windows.Forms.TextBox bytesToReadTextBox;
        private System.Windows.Forms.Label identifiedFileTypeLabelText;
        private System.Windows.Forms.Label identifiedFileTypeLabelValue;
    }
}