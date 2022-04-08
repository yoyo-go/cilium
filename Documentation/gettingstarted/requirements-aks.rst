To install Cilium on `Azure Kubernetes Service (AKS) <https://docs.microsoft.com/en-us/azure/aks/>`_,
perform the following steps:

**Default Configuration:**

=============== =================== ==============
Datapath        IPAM                Datastore
=============== =================== ==============
Direct Routing  Azure IPAM          Kubernetes CRD
=============== =================== ==============

.. tip::

   If you want to chain Cilium on top of the Azure CNI, refer to the guide
   :ref:`chaining_azure`.

**Requirements:**

* The AKS cluster must be created with ``--network-plugin none`` (BYOCNI) for
  compatibility with Cilium. See the `Bring your own CNI documentation
  <https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli>`_
  for more details about BYOCNI prerequisites / implications.

**Limitations:**

* All VMs and VM scale sets used in a cluster must belong to the same resource
  group.
