//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {


    /// <summary>
    /// OK, the thing is that I had to invent a function for creating a generic pool of objects that only stores
    /// the N latest used objects. Other objects which have not been used for a while shall be removed to minimise
    /// memory load. I am pretty sure someone else has done something simular before, and the method I'm using
    /// probably even has a name. I did however not find any simular implementation so I invented my own...
    /// 
    /// PopularityList is a SortedList that has a fixed max size. Intended use is when a similar functionality
    /// to a cache is wanted, i.e. the SortedList shall only hold the most recently used items.
    /// The PopularityList sorts all entries according to when they were accessed the last time.
    /// Unpopular entries will be removed from the list when new values are added to a full list.
    /// The list thereby behaves pretty much like a queue, but with fast (logarithmic) access to any elements
    /// through a key.
    /// 
    /// UPDATE:
    /// Erhm, well someone has done this before, it's called a Least Recently Used (LRU) Cache.
    /// </summary>
    /// 
    public class PopularityList<TKey, TValue> : IPopularityList<TKey, TValue> {

        public delegate bool ListCanExpand(PopularityList<TKey, TValue> list);

        public delegate void PopularityLostEventHandler(TKey key, TValue value);

        private Func<TValue, TValue, bool> lastValueHasExpired;

        public event PopularityLostEventHandler PopularityLost;

        //private System.Collections.Generic.SortedList<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>> sortedList;
        private System.Collections.Generic.Dictionary<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>> sortedList;
        private System.Collections.Generic.LinkedList<KeyValuePair<TKey, TValue>> linkedList;
        private int minPoolSize, maxPoolSize, currentPoolSize;
        private ListCanExpand listCanExpandDelegate;

        public int Count { get { return this.sortedList.Count; } }

        public PopularityList(int maxPoolSize) : this(maxPoolSize, maxPoolSize, null) { }

        public PopularityList(int minPoolSize, int maxPoolSize, ListCanExpand listCanExpandDelegate) : this(minPoolSize, maxPoolSize, listCanExpandDelegate, null) { }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="minPoolSize"></param>
        /// <param name="maxPoolSize"></param>
        /// <param name="listCanExpandDelegate"></param>
        /// <param name="lastValueHasExpired">TValue 1 = last item, TValue 2 = new item on Add</param>
        public PopularityList(int minPoolSize, int maxPoolSize, ListCanExpand listCanExpandDelegate, Func<TValue, TValue, bool> lastValueHasExpired) {
            this.minPoolSize = minPoolSize;
            this.maxPoolSize = maxPoolSize;
            this.currentPoolSize = this.minPoolSize;
            this.listCanExpandDelegate = listCanExpandDelegate;
            this.lastValueHasExpired = lastValueHasExpired;

            //this.sortedList = new SortedList<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>>();
            this.sortedList = new Dictionary<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>>();
            this.linkedList=new LinkedList<KeyValuePair<TKey, TValue>>();
        }

        /// <summary>
        /// O(log(n))
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(TKey key) {
            return sortedList.ContainsKey(key);
        }

        /// <summary>
        /// O(log(n))
        /// </summary>
        /// <param name="key"></param>
        public void Remove(TKey key, bool triggerPopularityLost = false) {
            LinkedListNode<KeyValuePair<TKey, TValue>> llNode=sortedList[key];//O(log(n))
            this.linkedList.Remove(llNode);//O(1)
            this.sortedList.Remove(key);//O(log(n))
            if(triggerPopularityLost)
                this.PopularityLost?.Invoke(key, llNode.Value.Value);
        }


        /// <summary>
        /// O(log(n))
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public TValue this[TKey key] {
            get {
                LinkedListNode<KeyValuePair<TKey, TValue>> llNode = this.sortedList[key];//O(log(n))
                this.linkedList.Remove(llNode);//O(1)
                this.linkedList.AddFirst(llNode);//O(1)
                return llNode.Value.Value;
            }
            set {
                if (this.sortedList.ContainsKey(key)) {
                    LinkedListNode<KeyValuePair<TKey, TValue>> llNode = this.sortedList[key];//O(log(n))
                    this.linkedList.Remove(llNode);//O(1)
                    this.linkedList.AddFirst(llNode);//O(1)
                    llNode.Value = new KeyValuePair<TKey, TValue>(key, value);
                }
                else
                    this.Add(key, value);
            }
        }

        /// <summary>
        /// O(log(n))
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        public void Add(TKey key, TValue value) {
            KeyValuePair<TKey, TValue> kvp=new KeyValuePair<TKey, TValue>(key, value);
            LinkedListNode<KeyValuePair<TKey, TValue>> llNode=new LinkedListNode<KeyValuePair<TKey, TValue>>(kvp);
            if(this.sortedList.ContainsKey(key)) {
                this.Remove(key);
            }
            this.linkedList.AddFirst(llNode);//O(1)
            this.sortedList.Add(key, llNode);//O(log(n))
                                        //see if there are too many values, if it is: remove one or several...

            if (this.lastValueHasExpired != null)
                while (this.linkedList.Last != null && this.lastValueHasExpired(linkedList.Last.Value.Value, value))
                    this.LastNodePopularityLost();
            while (this.sortedList.Count > this.currentPoolSize) {
                if (this.currentPoolSize < this.maxPoolSize && this.listCanExpandDelegate(this)) {
                    //extend list size
                    this.currentPoolSize = Math.Min(sortedList.Count, this.maxPoolSize);
                }
                else {
                    this.LastNodePopularityLost();
                }
            }
        }

        private void LastNodePopularityLost() {
            LinkedListNode<KeyValuePair<TKey, TValue>> lastNode = linkedList.Last;//O(1)
            this.sortedList.Remove(lastNode.Value.Key);//O(log(n))
            this.linkedList.Remove(lastNode);//O(1)
            //trigger an event to inform those who are interested that the node has become impopular
            this.PopularityLost?.Invoke(lastNode.Value.Key, lastNode.Value.Value);
        }

        public IEnumerable<TValue> GetValueEnumerator() {
            foreach(KeyValuePair<TKey, TValue> kvp in linkedList) {
                yield return kvp.Value;
            }
        }

        /// <summary>
        /// Gets an enumerator of items sorted on popularity (most popular first) from a selected item
        /// </summary>
        /// <param name="startKey">The most popular item to enumerate.
        /// Use null if all entries are to be enumerated</param>
        /// <returns></returns>
        public IEnumerable<KeyValuePair<TKey, TValue>> GetKeyValueEnumerator(TKey startKey) {
            //LinkedListNode<KeyValuePair<TKey,TValue> startNode = this.sortedList[startKey];

            if (startKey == null) {//return all items
                foreach (KeyValuePair<TKey, TValue> kvp in linkedList)
                    yield return kvp;
            }
            else {//return the not-so-popular items
                var currentNode = this.sortedList[startKey];
                while (currentNode != null) {
                    yield return currentNode.Value;
                    currentNode = currentNode.Next;
                }
            }
        }

        public void Clear() {
            this.linkedList.Clear();
            this.sortedList.Clear();
        }

    }
}
