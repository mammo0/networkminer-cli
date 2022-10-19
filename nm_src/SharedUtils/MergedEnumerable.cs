using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace SharedUtils
{
    public class MergedEnumerable<T> : IEnumerable<T> where T : class {


        private Func<T, T, bool> isBetter;
        private ICollection<IEnumerable<T>> enumerables;

        public MergedEnumerable(ICollection<IEnumerable<T>> enumerables, Func<T, T, bool> isBetter) {
            this.isBetter = isBetter;
            this.enumerables = enumerables;
        }

        public IEnumerator<T> GetEnumerator() {
            List<IEnumerator<T>> enumerators = new List<IEnumerator<T>>();
            foreach (var eles in enumerables)
                enumerators.Add(eles.GetEnumerator());
            return new AggregatedEnumerator(enumerators, this.isBetter);
        }

        IEnumerator IEnumerable.GetEnumerator() {
            return this.GetEnumerator();
        }

        public class AggregatedEnumerator : IEnumerator<T> {

            private ICollection<IEnumerator<T>> enumerators;
            private IEnumerator<T> currentEnumerator;
            private Func<T, T, bool> isBetter;

            public T Current {
                get {
                    return currentEnumerator?.Current;
                }
            }

            object IEnumerator.Current {
                get {
                    return currentEnumerator?.Current;
                }
            }

            public AggregatedEnumerator(ICollection<IEnumerator<T>> enumerators, Func<T, T, bool> isBetter) {
                this.enumerators = enumerators;
                this.isBetter = isBetter;
                this.currentEnumerator = null;
            }

            public bool MoveNext() {
                //figure out which enumerator has the best next value

                if (this.currentEnumerator == null) {
                    List<IEnumerator<T>> removeList = new List<IEnumerator<T>>();
                    foreach (IEnumerator<T> enumerator in this.enumerators)
                        if (!enumerator.MoveNext())
                            removeList.Add(enumerator);
                    foreach (IEnumerator<T> remove in removeList)
                        this.enumerators.Remove(remove);
                }
                else if (!this.currentEnumerator.MoveNext())
                    this.enumerators.Remove(this.currentEnumerator);

                this.currentEnumerator = null;
                foreach (IEnumerator<T> enumerator in this.enumerators) {
                    if (this.isBetter(enumerator.Current, this.currentEnumerator?.Current)) {
                        this.currentEnumerator = enumerator;
                    }
                }
                return this.currentEnumerator != null;
            }

            public void Reset() {
                this.currentEnumerator = null;
                foreach (var rator in this.enumerators)
                    rator.Reset();
            }

            #region IDisposable Support
            private bool disposedValue = false; // To detect redundant calls

            protected virtual void Dispose(bool disposing) {
                if (!disposedValue) {
                    if (disposing) {
                        foreach (var rator in this.enumerators)
                            rator.Dispose();
                        currentEnumerator = null;
                    }

                    disposedValue = true;
                }
            }

            public void Dispose() {
                // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
                Dispose(true);
            }
            #endregion

        }
    }
}
