/*
 *  DoDATGUI
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using System.Xml;

[assembly: System.Reflection.AssemblyTitle("DoDATGUI")]
[assembly: System.Reflection.AssemblyProduct("DoDATGUI")]
[assembly: System.Reflection.AssemblyVersion("0.4.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("0.4.0.0")]
[assembly: System.Runtime.InteropServices.ComVisible(false)]

class DoDATGUI : Form
{
    const string DoDatExeVersionString = "DoDAT v0.4";

    string OriginalText;
    private ComboBox cmbRunMode;

    DoDATGUI()
    {
        InitializeComponent();
        this.OriginalText = this.Text;
        this.Icon = System.Drawing.Icon.ExtractAssociatedIcon(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName);
    }

    [STAThread] static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        try
        {
            System.Diagnostics.Process testproc = new System.Diagnostics.Process();
            testproc.StartInfo.FileName = "DoDAT";
            testproc.StartInfo.RedirectStandardError = true;
            testproc.StartInfo.UseShellExecute = false;
            testproc.StartInfo.CreateNoWindow = true;
            testproc.Start();
            if (!testproc.StandardError.ReadToEnd().Contains(DoDatExeVersionString)) throw new Exception("Encountered wrong version of DoDAT program.");
        }
        catch (Exception e)
        {
            MessageBox.Show("DoDAT.exe could not be found. " + e.Message, "DoDAT - Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        DoDATGUI f = new DoDATGUI();
        string DATDir = "";

        Action refresh = () =>
        {
            bool on = (f.cmbGame.Items.Count > 0), isfix = (f.cmbRunMode.SelectedIndex == 2), verifyOrFix = (isfix || f.cmbRunMode.SelectedIndex == 1);
            f.txtInput.Enabled = f.btnInput.Enabled = (on && !verifyOrFix);
            f.txtOutput.Enabled = f.btnOutput.Enabled = on;
            f.cmbGame.Enabled = on;
            f.btnRun.Enabled = on;
            f.btnRun.Text = f.cmbRunMode.Text;

            if (f.txtInput.Text.Length == 0 || f.txtInput.ForeColor == SystemColors.ControlDark) { f.txtInput.Text = DATDir; }
            if (f.txtOutput.Text.Length == 0 || f.txtInput.ForeColor == SystemColors.ControlDark) { f.txtOutput.Text = DATDir; }
        };

        f.btnDAT.Click += (object sender, EventArgs e) =>
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.CheckPathExists = ofd.CheckFileExists = true;
            ofd.Filter =  "DAT XML files (*.xml)|*.xml|DAT XML files (*.dat)|*.dat|All files (*.*)|*.*";
            ofd.InitialDirectory = (DATDir.Length > 0 ? DATDir : Directory.GetCurrentDirectory());
            try { ofd.FileName = new FileInfo(f.txtDAT.Text).Name; } catch {}
            if (ofd.ShowDialog(f) != DialogResult.OK) { ofd.Dispose(); return; }
            f.txtDAT.Text = ofd.FileName;
            ofd.Dispose();
        };

        f.txtDAT.TextChanged += (object sender, EventArgs e) =>
        {
            try
            {
                if (f.txtDAT.Text.Length == 0 || !File.Exists(f.txtDAT.Text)) throw new Exception();
                object[] itms = new object[1024];
                int n = 1;
                using (XmlReader reader = XmlReader.Create(File.OpenRead(f.txtDAT.Text), new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Ignore }))
                    while (reader.Read())
                        if (reader.IsStartElement() && (reader.Name == "game" || reader.Name == "machine"))
                        {
                            string nm = reader.GetAttribute("name");
                            if (string.IsNullOrEmpty(nm)) continue;
                            if ((n % 1024) == 0) Array.Resize<object>(ref itms, n + 1024);
                            itms[n++] = nm;
                        }
                Array.Resize<object>(ref itms, n);
                itms[0] = " - Try All (" + (n - 1) + " Games) -";
                f.cmbGame.Items.Clear();
                f.cmbGame.Items.AddRange(itms);
                f.cmbGame.SelectedIndex = 0;
                DATDir = new FileInfo(f.txtDAT.Text).DirectoryName;
            } catch { f.cmbGame.Items.Clear(); f.cmbGame.Text = ""; DATDir = ""; }
            refresh();
        };
        f.cmbGame.Validated +=  (object sender, EventArgs e) => { if (f.cmbGame.Items.Count > 0 && f.cmbGame.SelectedIndex == -1) f.cmbGame.SelectedIndex = 0; };

        Action<TextBox> defaultToDATDir = (TextBox t) => { if (t.Text.Length == 0) t.Text = DATDir; t.ForeColor = (t.Text == DATDir ? SystemColors.ControlDark : SystemColors.WindowText); };
        Action<TextBox> browseDir = (TextBox t) =>
        {
            FolderBrowserDialog ofd = new FolderBrowserDialog();
            ofd.RootFolder = Environment.SpecialFolder.MyComputer;
            try { if (t.Text.Length > 0 && Directory.Exists(t.Text)) ofd.SelectedPath = t.Text; } catch { ofd.SelectedPath = ""; }
            if (ofd.SelectedPath.Length == 0) ofd.SelectedPath = (DATDir.Length > 0 ? DATDir : Directory.GetCurrentDirectory());
            if (ofd.ShowDialog(f) != DialogResult.OK) { ofd.Dispose(); return; }
            f.txtInput.Text = ofd.SelectedPath;
            ofd.Dispose();
        };
        f.txtInput.TextChanged += (object sender, EventArgs e) => defaultToDATDir(f.txtInput);
        f.txtOutput.TextChanged += (object sender, EventArgs e) => defaultToDATDir(f.txtOutput);
        f.btnInput.Click += (object sender, EventArgs e) => browseDir(f.txtInput);
        f.btnOutput.Click += (object sender, EventArgs e) => browseDir(f.txtInput);
        f.cmbRunMode.SelectedIndex = 0;
        f.cmbRunMode.SelectedIndexChanged += (object sender, EventArgs e) => refresh();
        f.btnQuit.Click += (object sender, EventArgs e) => f.DialogResult = DialogResult.Cancel;
        f.AllowDrop = true;
        f.DragEnter += (object sender, DragEventArgs e) =>
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        };
        f.DragDrop += (object sender, DragEventArgs e) =>
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string file in files)
                if (Path.GetExtension(file).Equals(".XML", StringComparison.InvariantCultureIgnoreCase) && File.Exists(file))
                    { f.txtDAT.Text = file; return; }
        };

        f.btnRun.Click += (object sender, EventArgs e) =>
        {
            f.txtLog.Text = "";

            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "DoDAT";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            System.Threading.Mutex m = new System.Threading.Mutex();
            System.Collections.Generic.List<string> logs = new System.Collections.Generic.List<string>();
            process.OutputDataReceived += (sendingProcess, outLine) => { m.WaitOne(); logs.Add(outLine.Data); m.ReleaseMutex(); };
            process.ErrorDataReceived  += (sendingProcess, errLine) => { m.WaitOne(); logs.Add(errLine.Data); m.ReleaseMutex(); };

            process.StartInfo.Arguments = "-q -s \"" + f.txtInput.Text + "\" -o \"" + f.txtOutput.Text + "\"";
            if (f.cmbRunMode.SelectedIndex == 2) process.StartInfo.Arguments += " -f";
            if (f.cmbRunMode.SelectedIndex == 1) process.StartInfo.Arguments += " -v";

            f.progress.Visible = true;
            if (f.cmbGame.SelectedIndex == 0)
            {
                process.StartInfo.Arguments += " -x \"" + f.txtDAT.Text + "\"";
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
            }
            else
            {
                process.StartInfo.Arguments += " -x -";
                process.StartInfo.RedirectStandardInput = true;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                string val = f.cmbGame.SelectedItem as string;
                using (XmlReader reader = XmlReader.Create(File.OpenRead(f.txtDAT.Text), new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Ignore }))
                    while (reader.Read())
                        if (reader.IsStartElement() && reader.GetAttribute("name") == val && (reader.Name == "game" || reader.Name == "machine"))
                        {
                            StreamWriter stdin = process.StandardInput;
                            stdin.WriteLine(reader.ReadOuterXml() + Environment.NewLine);
                            stdin.Close();
                            break;
                        }
            }
            while (!process.WaitForExit(1))
            {
                if (logs.Count > 0) { m.WaitOne(); foreach (string s in logs) f.txtLog.Text += s + Environment.NewLine; logs.Clear(); m.ReleaseMutex(); f.txtLog.Select(f.txtLog.Text.Length, 0); f.txtLog.ScrollToCaret(); }
                Application.DoEvents();
            }
            if (logs.Count > 0) { m.WaitOne(); foreach (string s in logs) f.txtLog.Text += s + Environment.NewLine; logs.Clear(); m.ReleaseMutex(); f.txtLog.Select(f.txtLog.Text.Length, 0); f.txtLog.ScrollToCaret(); }
            f.progress.Visible = false;
        };

        if (args.Length > 0) f.txtDAT.Text = args[0];
        else refresh();

        f.ShowDialog();
    }

    public TextBox txtDAT;
    public Button btnDAT;
    private Label label1;
    public Button btnInput;
    public TextBox txtInput;
    private Label label2;
    public Button btnOutput;
    public TextBox txtOutput;
    private Label label3;
    private GroupBox groupBox1;
    private Label label4;
    private ComboBox cmbGame;
    private Button btnQuit;
    private Button btnRun;
    private ProgressBar progress;
    private TextBox txtLog;

    /// <summary>
    /// Required designer variable.
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    /// Clean up any resources being used.
    /// </summary>
    /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    /// <summary>
    /// Required method for Designer support - do not modify
    /// the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
            this.label1 = new System.Windows.Forms.Label();
            this.btnDAT = new System.Windows.Forms.Button();
            this.txtDAT = new System.Windows.Forms.TextBox();
            this.btnInput = new System.Windows.Forms.Button();
            this.txtInput = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.btnOutput = new System.Windows.Forms.Button();
            this.txtOutput = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.txtLog = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.cmbGame = new System.Windows.Forms.ComboBox();
            this.btnQuit = new System.Windows.Forms.Button();
            this.btnRun = new System.Windows.Forms.Button();
            this.progress = new System.Windows.Forms.ProgressBar();
            this.cmbRunMode = new System.Windows.Forms.ComboBox();
            this.groupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 16);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(90, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "Select DAT XML:";
            // 
            // btnDAT
            // 
            this.btnDAT.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnDAT.Location = new System.Drawing.Point(580, 11);
            this.btnDAT.Name = "btnDAT";
            this.btnDAT.Size = new System.Drawing.Size(33, 22);
            this.btnDAT.TabIndex = 2;
            this.btnDAT.Text = "...";
            this.btnDAT.UseVisualStyleBackColor = true;
            // 
            // txtDAT
            // 
            this.txtDAT.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtDAT.Location = new System.Drawing.Point(123, 12);
            this.txtDAT.Name = "txtDAT";
            this.txtDAT.Size = new System.Drawing.Size(451, 20);
            this.txtDAT.TabIndex = 1;
            // 
            // btnInput
            // 
            this.btnInput.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnInput.Location = new System.Drawing.Point(580, 39);
            this.btnInput.Name = "btnInput";
            this.btnInput.Size = new System.Drawing.Size(33, 22);
            this.btnInput.TabIndex = 5;
            this.btnInput.Text = "...";
            this.btnInput.UseVisualStyleBackColor = true;
            // 
            // txtInput
            // 
            this.txtInput.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtInput.Location = new System.Drawing.Point(123, 40);
            this.txtInput.Name = "txtInput";
            this.txtInput.Size = new System.Drawing.Size(451, 20);
            this.txtInput.TabIndex = 4;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(12, 44);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(90, 13);
            this.label2.TabIndex = 3;
            this.label2.Text = "Input Files Folder:";
            // 
            // btnOutput
            // 
            this.btnOutput.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnOutput.Location = new System.Drawing.Point(580, 67);
            this.btnOutput.Name = "btnOutput";
            this.btnOutput.Size = new System.Drawing.Size(33, 22);
            this.btnOutput.TabIndex = 8;
            this.btnOutput.Text = "...";
            this.btnOutput.UseVisualStyleBackColor = true;
            // 
            // txtOutput
            // 
            this.txtOutput.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtOutput.Location = new System.Drawing.Point(123, 68);
            this.txtOutput.Name = "txtOutput";
            this.txtOutput.Size = new System.Drawing.Size(451, 20);
            this.txtOutput.TabIndex = 7;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 72);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(98, 13);
            this.label3.TabIndex = 6;
            this.label3.Text = "Output Files Folder:";
            // 
            // groupBox1
            // 
            this.groupBox1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox1.Controls.Add(this.txtLog);
            this.groupBox1.Location = new System.Drawing.Point(15, 154);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(598, 316);
            this.groupBox1.TabIndex = 15;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Log";
            // 
            // txtLog
            // 
            this.txtLog.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtLog.Location = new System.Drawing.Point(7, 20);
            this.txtLog.Multiline = true;
            this.txtLog.Name = "txtLog";
            this.txtLog.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtLog.Size = new System.Drawing.Size(585, 290);
            this.txtLog.TabIndex = 0;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(12, 101);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(105, 13);
            this.label4.TabIndex = 9;
            this.label4.Text = "Build Specific Game:";
            // 
            // cmbGame
            // 
            this.cmbGame.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.cmbGame.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cmbGame.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cmbGame.FormattingEnabled = true;
            this.cmbGame.Location = new System.Drawing.Point(123, 97);
            this.cmbGame.Name = "cmbGame";
            this.cmbGame.Size = new System.Drawing.Size(490, 21);
            this.cmbGame.TabIndex = 10;
            // 
            // btnQuit
            // 
            this.btnQuit.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnQuit.Location = new System.Drawing.Point(537, 125);
            this.btnQuit.Name = "btnQuit";
            this.btnQuit.Size = new System.Drawing.Size(75, 23);
            this.btnQuit.TabIndex = 14;
            this.btnQuit.Text = "Quit";
            this.btnQuit.UseVisualStyleBackColor = true;
            // 
            // btnRun
            // 
            this.btnRun.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnRun.Location = new System.Drawing.Point(404, 125);
            this.btnRun.Name = "btnRun";
            this.btnRun.Size = new System.Drawing.Size(110, 23);
            this.btnRun.TabIndex = 12;
            this.btnRun.Text = "Run";
            this.btnRun.UseVisualStyleBackColor = true;
            // 
            // progress
            // 
            this.progress.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.progress.Location = new System.Drawing.Point(15, 126);
            this.progress.Name = "progress";
            this.progress.Size = new System.Drawing.Size(383, 21);
            this.progress.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            this.progress.TabIndex = 11;
            this.progress.Visible = false;
            // 
            // cmbRunMode
            // 
            this.cmbRunMode.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.cmbRunMode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbRunMode.FormattingEnabled = true;
            this.cmbRunMode.ItemHeight = 13;
            this.cmbRunMode.Items.AddRange(new object[] {
            "Build Game(s)",
            "Verify Game(s)",
            "Fix Game(s)"});
            this.cmbRunMode.Location = new System.Drawing.Point(405, 126);
            this.cmbRunMode.Name = "cmbRunMode";
            this.cmbRunMode.Size = new System.Drawing.Size(126, 21);
            this.cmbRunMode.TabIndex = 13;
            // 
            // DoDATGUI
            // 
            this.AllowDrop = true;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.Window;
            this.ClientSize = new System.Drawing.Size(625, 482);
            this.Controls.Add(this.progress);
            this.Controls.Add(this.btnRun);
            this.Controls.Add(this.btnQuit);
            this.Controls.Add(this.cmbGame);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.btnOutput);
            this.Controls.Add(this.txtOutput);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.btnInput);
            this.Controls.Add(this.txtInput);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.btnDAT);
            this.Controls.Add(this.txtDAT);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.cmbRunMode);
            this.Name = "DoDATGUI";
            this.Text = "DoDAT";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

    }
    #endregion
}
