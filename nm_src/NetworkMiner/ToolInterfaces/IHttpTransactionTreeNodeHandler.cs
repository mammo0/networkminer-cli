using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IHttpTransactionTreeNodeHandler {

        System.Windows.Forms.TreeNode GetTreeNode(string httpClientId);
        Tuple<System.Net.IPAddress, DateTime> GetServerIp(System.Windows.Forms.TreeNode treeNode);
        string GetServerHostname(System.Windows.Forms.TreeNode treeNode);
        string GetUrl(System.Windows.Forms.TreeNode treeNode);

        void SetNetworkMinerForm(NetworkMinerForm form);

        void ShowTransactionProperties(System.Windows.Forms.TreeNode treeNode, System.Windows.Forms.PropertyGrid propertyGrid);
        bool Matches(System.Windows.Forms.TreeNode treeNode, string searchString, bool caseSensitive);

        bool IsAdvertisment(string url);
        bool IsInternetTracker(string url);
    }
}
