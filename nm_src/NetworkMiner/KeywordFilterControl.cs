using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Text;
using System.Windows.Forms;
using System.Windows.Forms.Design;
using System.Text.RegularExpressions;

namespace NetworkMiner {
    public partial class KeywordFilterControl<T> : UserControl {

        public static void RegisterFilterControlCallback(ListView listView, KeywordFilterControl<ListViewItem> filterControl) {
            filterControl.ClearItemsCallback = new KeywordFilterControl<ListViewItem>.ClearItems(listView.Items.Clear);
            filterControl.SetItemsVisibleCallback = new KeywordFilterControl<ListViewItem>.SetItemsVisible((visible) => { listView.Visible = visible; });
            filterControl.AddItemCallback = new KeywordFilterControl<ListViewItem>.AddItem((item) => { listView.Items.Add(item); });
            //filterControl.AddItemRangeCallback = new KeywordFilterControl<ListViewItem>.AddItemRange(listView.Items.AddRange);
            
            filterControl.AddItemRangeCallback = new KeywordFilterControl<ListViewItem>.AddItemRange((items) => {
                listView.BeginUpdate();
                listView.Items.AddRange(items);
                listView.EndUpdate();
                });
                
            filterControl.BeginUpdateListView = delegate {
                listView.SuspendLayout();
                listView.BeginUpdate();
            };
            filterControl.EndUpdateListView = delegate {
                listView.EndUpdate();
                listView.ResumeLayout();
            };

            if(listView.Columns.Count > 1) {
                
                foreach(System.Windows.Forms.ColumnHeader c in listView.Columns) {
                    filterControl.columnComboBox.Items.Add(c.Text);
                }
                filterControl.columnComboBox.SelectedIndex = 0;
            }
        }


        public delegate void ClearItems();

        public delegate void SetItemsVisible(bool visible);
        public delegate void AddItem(T item);
        public delegate void AddItemRange(T[] items);


        //public ListView ListView;
        public List<T> UnfilteredList;

        public ClearItems ClearItemsCallback;

        [Obsolete("SetItemsVisible is deprecated since a bug in Mono causes column headers to remain invisible, please use BeginUpdateListView and EndUpdateListView instead.")]
        public SetItemsVisible SetItemsVisibleCallback = null;
        public AddItem AddItemCallback;
        public AddItemRange AddItemRangeCallback;
        public EventHandler BeginUpdateListView, EndUpdateListView;

        private KeywordFilter currentKeywordFilter = null;

        public KeywordFilterControl() {
            InitializeComponent();
            this.UnfilteredList = new List<T>();
            this.filterModeComboBox.Items.Clear();
            foreach(string mode in Enum.GetNames(typeof(KeywordFilter.FilterMode))) {
                int index = this.filterModeComboBox.Items.Add(mode);
            }
            this.filterModeComboBox.SelectedIndex = 0;//ExactString
        }

        protected void SetLabel(string label) {
            this.label1.Text = label;
        }

        
        
        protected override void SetBoundsCore(int x, int y, int width, int height, BoundsSpecified specified) {
            // Set a fixed height for the control.
            base.SetBoundsCore(x, y, width, 22, specified);
        }
        

        public void Add(T item) {
            this.UnfilteredList.Add(item);

            if (this.currentKeywordFilter == null || this.currentKeywordFilter.Matches(item)) {
                //this.ListView.Items.Add(item);
                this.AddItemCallback(item);
            }
        }

        public void AddRange(IEnumerable<T> items) {
            
            this.UnfilteredList.AddRange(items);
            
            List<T> filteredItems = new List<T>();
            foreach (T item in items) {
                if (this.currentKeywordFilter == null || this.currentKeywordFilter.Matches(item)) {
                    //this.AddItemCallback(items);
                    filteredItems.Add(item);
                }
            }
            
            //this.BeginUpdateListView?.Invoke(this, EventArgs.Empty);
            this.AddItemRangeCallback?.Invoke(filteredItems.ToArray());
            //this.AddItemRangeCallback?.BeginInvoke(filteredItems.ToArray(), null, null);//causes thread problems related to GUI
            //this.EndUpdateListView?.Invoke(this, EventArgs.Empty);
            
        }
        
        private void applyKeywordButton_Click(object sender, EventArgs e) {
            KeywordFilter.FilterMode filterMode = (KeywordFilter.FilterMode)Enum.Parse(typeof(KeywordFilter.FilterMode), this.filterModeComboBox.SelectedItem.ToString());
            KeywordFilter filter = new KeywordFilter(this.keywordComboBox.Text, filterMode, this.caseSensitiveCheckBox.Checked, this.columnComboBox.SelectedIndex);

            this.currentKeywordFilter = filter;
            if(filter.InputString == null || filter.InputString.Length == 0)
                this.keywordComboBox.BackColor = System.Drawing.SystemColors.Window;
            else {
                this.keywordComboBox.BackColor = Color.LightGreen;
                bool newKeyword = true;
                foreach (Object item in this.keywordComboBox.Items)
                    if (this.keywordComboBox.Text.Equals(item)) {
                        newKeyword = false;
                        break;
                    }
                if (newKeyword)
                    this.keywordComboBox.Items.Add(this.keywordComboBox.Text);
            }


            this.BeginUpdateListView?.Invoke(this, EventArgs.Empty);

            
            if (this.currentKeywordFilter == null || this.currentKeywordFilter.InputString == null || this.currentKeywordFilter.InputString.Length == 0) {
                this.ClearItemsCallback();
                this.AddItemRangeCallback(this.UnfilteredList.ToArray());
            }
            else {
                try {
                    List<T> itemList = new List<T>();
                    foreach (T item in this.UnfilteredList) {
                        if (this.currentKeywordFilter == null || this.currentKeywordFilter.Matches(item)) {
                            itemList.Add(item);
                        }
                    }
                    this.ClearItemsCallback();
                    this.AddItemRangeCallback(itemList.ToArray());
                }
                catch(Exception keywordException) {
                    this.currentKeywordFilter = null;
                    this.keywordComboBox.BackColor = System.Drawing.SystemColors.Window;
                    //this.AddItemRangeCallback(this.UnfilteredList.ToArray());
                    MessageBox.Show(this, keywordException.Message, "Invalid Keyword Filter");
                }
            }
            this.EndUpdateListView?.Invoke(this, EventArgs.Empty);
        }


        private void clearKeywordButton_Click(object sender, EventArgs e) {
            this.keywordComboBox.Text = "";
            this.applyKeywordButton_Click(sender, e);
        }

        

        /// <summary>
        /// Sets the textbox color to green if the current input is equal to the active filter
        /// </summary>
        private void validateInputSettings(object sender, EventArgs e) {
            if (this.keywordComboBox.Text == null || this.keywordComboBox.Text.Length == 0 || this.currentKeywordFilter == null || !this.keywordComboBox.Text.Equals(this.currentKeywordFilter.InputString) || this.caseSensitiveCheckBox.Checked != this.currentKeywordFilter.CaseSensitive || !this.filterModeComboBox.SelectedText.Equals(this.currentKeywordFilter.InputFilterMode.ToString())) {
                if (this.keywordComboBox.BackColor != System.Drawing.SystemColors.Window)
                    this.keywordComboBox.BackColor = System.Drawing.SystemColors.Window;
            }
            else if (this.keywordComboBox.Text.Equals(this.currentKeywordFilter.InputString) && this.caseSensitiveCheckBox.Checked == this.currentKeywordFilter.CaseSensitive && this.filterModeComboBox.SelectedText.Equals(this.currentKeywordFilter.InputFilterMode.ToString()))
                if (this.keywordComboBox.BackColor != Color.LightGreen)
                    this.keywordComboBox.BackColor = Color.LightGreen;
        }

        private void keywordComboBox_KeyDown(object sender, KeyEventArgs e) {
            if (e.KeyCode == Keys.Enter) {
                this.applyKeywordButton_Click(sender, e);
                e.Handled = true;
                e.SuppressKeyPress = true;//to disable the "Ding" sound
            }
            else if (e.KeyCode == Keys.Escape) {
                if (this.currentKeywordFilter != null && this.currentKeywordFilter.InputString != null) { //if (this.keywordComboBox.Tag is string) {
                    this.keywordComboBox.Text = this.currentKeywordFilter.InputString; //this.keywordComboBox.Text = this.keywordComboBox.Tag as string;
                    //this.keywordFilterComboBox.BackColor = Color.LightGreen;
                }
                else {
                    this.keywordComboBox.Text = "";
                    //this.keywordFilterComboBox.BackColor = System.Drawing.SystemColors.Window;
                }
            }
        }

        public void Clear() {
            this.UnfilteredList.Clear();
            this.clearKeywordButton_Click(null, null);
        }

        internal class KeywordFilter {
            public enum FilterMode { ExactPhrase, AllWords, AnyWord, RegEx }

            public string InputString;
            public FilterMode InputFilterMode;
            public bool CaseSensitive;
            public int ColumnIndex;

            internal KeywordFilter(string filterString, FilterMode filterMode, bool caseSensitive, int columnIndex)
            {
                this.InputString = filterString;
                this.InputFilterMode = filterMode;
                this.CaseSensitive = caseSensitive;
                this.ColumnIndex = columnIndex;
            }

            internal bool Matches(T item) {
                return matches(item, this.InputString, this.InputFilterMode, this.CaseSensitive, this.ColumnIndex);
                
            }

            private static bool matches(T item, string filterString, FilterMode inputFilterMode, bool caseSensitive, int columnIndex) {
                if (filterString == null || filterString == String.Empty)
                    return true;
                if (inputFilterMode == FilterMode.ExactPhrase) {

                    if (caseSensitive) {
                        if (item is ListViewItem) {
                            ListViewItem listViewItem = item as ListViewItem;
                            return matchesExactPhrase(listViewItem, text => text?.Contains(filterString) == true, columnIndex);
                        }
                        else if (item is TreeNode) {
                            TreeNode treeNode = item as TreeNode;
                            if (treeNode.Text.Contains(filterString))
                                return true;
                        }
                        else
                            throw new NotImplementedException();
                    }
                    else {
                        if (item is ListViewItem) {
                            ListViewItem listViewItem = item as ListViewItem;
                            return matchesExactPhrase(listViewItem, text => System.Globalization.CultureInfo.InvariantCulture.CompareInfo.IndexOf(text, filterString, System.Globalization.CompareOptions.IgnoreCase) >= 0, columnIndex);
                        }
                        else if (item is TreeNode) {
                            TreeNode treeNode = item as TreeNode;
                            if (System.Globalization.CultureInfo.InvariantCulture.CompareInfo.IndexOf(treeNode.Text, filterString, System.Globalization.CompareOptions.IgnoreCase) >= 0)
                                return true;
                        }
                        else
                            throw new NotImplementedException();
                    }
                    return false;
                }
                else if (inputFilterMode == FilterMode.AllWords) {
                    string[] inputWords = filterString.Split(null);
                    foreach (string word in inputWords)
                        if (!matches(item, word, FilterMode.ExactPhrase, caseSensitive, columnIndex))
                            return false;
                    return true;
                }
                else if (inputFilterMode == FilterMode.AnyWord) {

                    string[] inputWords = filterString.Split(null);
                    foreach (string word in inputWords) {
                        if (matches(item, word, FilterMode.ExactPhrase, caseSensitive, columnIndex))
                            return true;
                    }
                    return false;
                }
                else if (inputFilterMode == FilterMode.RegEx) {

                    Regex regex = new Regex(filterString);
                    if (item is ListViewItem) {
                        ListViewItem listViewItem = item as ListViewItem;
                        return matchesExactPhrase(listViewItem, text => regex.IsMatch(text), columnIndex);
                    }
                    else if (item is TreeNode) {
                        TreeNode treeNode = item as TreeNode;
                        if (regex.IsMatch(treeNode.Text))
                            return true;
                    }
                    else
                        throw new NotImplementedException();
                    return false;
                }
                else
                    throw new Exception("Invalid FilterMode");
            }

            private static bool matchesExactPhrase(ListViewItem listViewItem, Func<string, bool> filterContains, int columnIndex) {
                if (columnIndex > 0) {
                    if (filterContains(listViewItem.SubItems[columnIndex - 1].Text))
                        return true;
                }
                else {
                    foreach (ListViewItem.ListViewSubItem subItem in listViewItem.SubItems)
                        if(filterContains(subItem.Text))
                            return true;
                    if (listViewItem.Tag is IEnumerable<string>) {
                        foreach (string attribute in (listViewItem.Tag as IEnumerable<string>))
                            if (filterContains(attribute))
                                return true;
                    }
                    else if(listViewItem.Tag is string s) {
                        if (filterContains(s))
                            return true;
                    }
                    else if(listViewItem.Tag is KeyValuePair<string, string> kvp) {
                        if (filterContains(kvp.Key))
                            return true;
                        if (filterContains(kvp.Value))
                            return true;
                    }

                    else if (listViewItem.Tag is Tuple<System.Collections.Specialized.NameValueCollection, byte[], Encoding> tuple) {
                        foreach (string key in tuple.Item1.Keys) {
                            if (filterContains(key))//email header name
                                return true;
                            if (filterContains(tuple.Item1[key]))//email header value
                                return true;
                        }
                        try {
                            if (filterContains(tuple.Item3.GetString(tuple.Item2)))//email body
                                return true;
                        }
                        catch {
                            //Pokemon exception handling, "Gotta catch 'em all"
                            SharedUtils.Logger.Log("Unable to decode email body for keyword filter search.", SharedUtils.Logger.EventLogEntryType.Error);
                        }
                    }
#if DEBUG
                    else if(listViewItem.Tag != null) {
                        //unknown tag?
                        Type t = listViewItem.Tag.GetType();
                        System.Diagnostics.Debugger.Break();
                    }
#endif

                }
                return false;
            }
        }

    }
}
