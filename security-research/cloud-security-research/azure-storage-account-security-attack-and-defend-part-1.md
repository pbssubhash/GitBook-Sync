---
description: >-
  Azure Storage Account is a premium storage offering from Microsoft that's used
  by several large firms. This blog outlines various ways to attack and defend
  the same.
cover: >-
  https://images.unsplash.com/photo-1553413077-190dd305871c?crop=entropy&cs=srgb&fm=jpg&ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHwxfHxzdG9yYWdlfGVufDB8fHx8MTcwNDU5OTEzMnww&ixlib=rb-4.0.3&q=85
coverY: 0
layout:
  cover:
    visible: true
    size: full
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Azure Storage Account Security - Attack & Defend: Part 1

{% hint style="danger" %}
The information provided is for educational purpose only. I believe you have a conscience and you won't screw innocent companies for your fun and profit. I'm not responsible for any actions that anyone would do with this. This is intended for defenders to get visibility into attacks that are possible. **Please don't be evil. 🥺**
{% endhint %}

***

## 😊 Introduction to the Service

#### ⏭️ Overview

Azure Storage Account is a logical offering that groups various data services from Azure storage. These services include:

1. **Blobs:** It's for plain unstructured data like images, videos and documents. This can typically be compared with S3 Blob storage service.
2. **Files:** This provides a Network file system interface for sharing files across multiple platforms and avenues like SMB shares, FTP, etc.
3. **Queues:** This is a multi-way communication channel where providers and consumers can put messages and consume messages from the queue. This enables async communication between processes too.
4. **Tables:** This is a NoSQL data store that's comparable to hosted Mongo DB. Although, there's another hosted NoSQL DB offering from Azure, this is a fast alternative without too many open strings.

#### ⏭️ Key Terminology

The following are few key things that are associated with an Azure Storage Account (from security POV):

#### 1. Subscription ID:

Subscription ID is a logical segregation that's intended for separate billing methods. This is more often used for varied business purposes.&#x20;

#### 2. Resource Group:

Resource group is a logical group of resources intended for a similar purpose or a project. This is more a technical segregation of resources for better manageability.&#x20;

For more information about Azure account hierarchy, please visit this [page](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/organize-subscriptions).

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption><p>Credit: Microsoft documentation</p></figcaption></figure>

#### 3. Storage Account Name

It's the name associated with a storage account. The following are the constraints for a storage account:

* It must be between 3 and 24 characters.
* Can only contain lowercase letters and numbers (no special chars like "-", etc.)
* Should be unique across Azure cloud. No two storage accounts can contain the same name.
* Can't contain certain reserved words. Currently observed reserved words: "Microsoft"

#### 4. Namespace:

Each object in Azure storage has a unique URL (including the storage account name).&#x20;

#### 5. Types of storage accounts

Azure storage account supports variety of types. These allow for optimized use of resources and lesser cost. The following are types of storage accounts:

* Standard general purpose v2
* Premium block blobs
* Premium file shares
* Premium page blobs
* Legacy (doesn't use SSDs)

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption><p>Credit: Microsoft Documentation</p></figcaption></figure>

## 🚪Access Model

This section will cover ways in which access to data is restricted in Azure storage account.

#### 1. Identity based restriction

Access to Azure storage account is primarily controlled in 3 ways:

* <mark style="color:blue;">**RBAC for Azure AD accounts:**</mark> By default, no account has access to a storage account's data. The administrator of the resource group/subscription/management group/tenant will have access to modifying the properties but can't directly access it. They can modify access control settings to add their user identity (or service principal) to authorized list. Hence all the users having privileged access to the subscription/resource group and tenant should be considered to have access. There are several roles that are defined in Azure, that can be used to provision fine grained access control. The full list can be viewed here: [Built in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles). However, I consider the following roles to be very important. Any user with the following roles should be protected at all costs to ensure that storage accounts are secure.&#x20;

<table data-full-width="false"><thead><tr><th width="179">Name of the Role</th><th>Description</th><th>Importance</th><th data-hidden>Description</th><th data-hidden>Importance</th><th data-hidden data-type="number"></th></tr></thead><tbody><tr><td>Owner</td><td>Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.</td><td>This provides access to the resource. An adversary can modify properties of the resource and get access sensitive data.</td><td>Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.</td><td></td><td>null</td></tr><tr><td>Contributor</td><td>Grants full access to manage all resources but does not allow you to assign roles in Azure RBAC, manage assignments in Azure Blueprints, or share image galleries.</td><td>This provides access to the resource. An adversary can modify properties of the resource and get access sensitive data.</td><td>Grants full access to manage all resources but does not allow you to assign roles in Azure RBAC, manage assignments in Azure Blueprints, or share image galleries.</td><td></td><td>null</td></tr><tr><td>Role Based Access Control Administrator</td><td>Manage access to Azure resources by assigning roles using Azure RBAC. This role does not allow you to manage access using other ways, such as Azure Policy.</td><td>This provides ability to add roles to another user. Using this, an adversary can provision access to an attacker controlled account.</td><td>Manage access to Azure resources by assigning roles using Azure RBAC. This role does not allow you to manage access using other ways, such as Azure Policy.</td><td></td><td>null</td></tr><tr><td>User Access Administrator</td><td>Lets you manage user access to Azure resources.</td><td>This provides ability to add roles to another user. Using this, an adversary can provision access to an attacker controlled account.</td><td>Lets you manage user access to Azure resources.</td><td></td><td>null</td></tr><tr><td>Reader and Data Access</td><td>Lets you view everything but will not let you delete or create a storage account or contained resource. It will also allow read/write access to all data contained in a storage account via access to storage account keys.</td><td>An adversary with this role can view sensitive data.</td><td>Lets you view everything but will not let you delete or create a storage account or contained resource. It will also allow read/write access to all data contained in a storage account via access to storage account keys.</td><td></td><td>null</td></tr><tr><td>Storage Account Contributor</td><td>Lets you manage storage accounts, including accessing storage account keys which provide full access to storage account data.</td><td>An adversary with this role can view sensitive data.</td><td>Lets you manage storage accounts, including accessing storage account keys which provide full access to storage account data.</td><td></td><td>null</td></tr><tr><td>Storage Account Key Operator Service Role</td><td>Storage Account Key Operators are allowed to list and regenerate keys on Storage Accounts.</td><td>An adversary with this role can exfiltrate keys to access sensitive data or regenerate keys to create denial of service (making the older key unusable and thus all downstream applications unusable)</td><td>Storage Account Key Operators are allowed to list and regenerate keys on Storage Accounts</td><td></td><td>null</td></tr><tr><td>Storage Blob Data Contributor</td><td>Allows for read, write and delete access to Azure Storage blob containers and data.</td><td>An adversary with this role can view sensitive data, modify properties of a storage account.</td><td>Allows for read, write and delete access to Azure Storage blob containers and data</td><td></td><td>null</td></tr><tr><td>Storage Blob Data Owner</td><td>Allows for full access to Azure Storage blob containers and data, including assigning POSIX access control.</td><td>An adversary with this role can view sensitive data, modify properties of a storage account.</td><td>Allows for full access to Azure Storage blob containers and data, including assigning POSIX access control.</td><td></td><td>null</td></tr><tr><td>Storage Blob Data Reader</td><td>Allows for read access to Azure Storage blob containers and data.</td><td>An adversary with this role can view sensitive data, modify properties of a storage account.</td><td>Allows for read access to Azure Storage blob containers and data</td><td></td><td>null</td></tr><tr><td>Storage Blob Delegator</td><td>Allows for generation of a user delegation key which can be used to sign SAS tokens.</td><td>An adversary with this role can generate a new key that is used to generate SAS tokens. </td><td>Allows for generation of a user delegation key which can be used to sign SAS tokens</td><td></td><td>null</td></tr><tr><td>Storage File Data SMB Share Contributor</td><td>Allows for read, write, and delete access in Azure Storage file shares over SMB.</td><td>An adversary with this role can view sensitive data, modify properties affecting SMB access of the storage account.</td><td>Allows for read, write, and delete access in Azure Storage file shares over SMB</td><td></td><td>null</td></tr><tr><td>Storage File Data SMB Share Elevated Contributor</td><td>Allows for read, write, delete and modify NTFS permission access in Azure Storage file shares over SMB.</td><td>An adversary with this role can view sensitive data, modify properties affecting SMB access of the storage account.</td><td>Allows for read, write, delete and modify NTFS permission access in Azure Storage file shares over SMB</td><td></td><td>null</td></tr><tr><td>Storage File Data SMB Share Reader</td><td>Allows for read access to Azure File Share over SMB.</td><td>An adversary with this role can view sensitive data, affecting SMB access of the sto<em>rage</em> account<em>.</em></td><td>Allows for read access to Azure File Share over SMB</td><td></td><td>null</td></tr><tr><td>Storage Queue Data Contributor</td><td>Allows for read, write, and delete access to Azure Storage queues and queue messages.</td><td>An adversary with this role can view sensitive data, modify properties.</td><td>Allows for read, write, and delete access to Azure Storage queues and queue messages</td><td></td><td>null</td></tr><tr><td>Storage Queue Data Reader</td><td>Allows for read access to Azure Storage queues and queue messages.</td><td>An adversary with this role can view sensitive queue messages.</td><td>Allows for read access to Azure Storage queues and queue messages</td><td></td><td>null</td></tr><tr><td>Storage Queue Data Message Processor</td><td>Allows for peek, receive, and delete access to Azure Storage queue messages.</td><td>An adversary with this role can view sensitive queue messages.</td><td>Allows for peek, receive, and delete access to Azure Storage queue messages</td><td></td><td>null</td></tr><tr><td>Storage Queue Data Reader</td><td>Allows for read access to Azure Storage queues and queue messages.</td><td>An adversary with this role can view sensitive queue messages.</td><td>Allows for read access to Azure Storage queues and queue messages</td><td></td><td>null</td></tr><tr><td>Storage Table Data Contributor</td><td>Allows for read, write and delete access to Azure Storage tables and entities.</td><td>An adversary with this role can view sensitive table data.</td><td>Allows for read, write and delete access to Azure Storage tables and entities</td><td></td><td>null</td></tr><tr><td>Storage Table Data Reader</td><td>Allows for read access to Azure Storage tables and entities.</td><td>An adversary with this role can view sensitive table data.</td><td>Allows for read access to Azure Storage tables and entities</td><td></td><td>null</td></tr></tbody></table>

* Access Keys + Shared Access Signature: This is another way of accessing storage accounts and data within the storage account. When a storage account is created, a 512-bit storage account key is created. This is used to sign and create a signature. This signature can be created to restrict access to one object or blob or an entire storage account. The following are created:
  * Connection String: Can be used with [Azure Storage Explorer](https://azure.microsoft.com/en-in/products/storage/storage-explorer) or [Official Microsoft Libraries](https://azure.microsoft.com/en-in/downloads/).
  * SAS Token: This can be appended behind an object/container to access the data.
  * Blob service SAS URL: This is used to access the objects inside Blog.
  * Queue service SAS URL: This is used to access data inside Queue.
  * Table service SAS URL: This is used to access data inside Table data.

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>Different SAS URLs</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption><p>Access Keys</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption><p>Creation of SAS</p></figcaption></figure>

#### 2. Network based restriction.

The following are the network-based features that allow for network isolation.

*   <mark style="color:blue;">**Firewall and Virtual Networks:**</mark> You can expose a storage account to an Azure virtual network or just whitelist a single IP address/CIDR.&#x20;

    <figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption><p>Firewall based restrictions.</p></figcaption></figure>


*   <mark style="color:blue;">**Resource specific restrictions:**</mark> Storage account can be exposed only to specific resources (eg. virtual machines). This is very useful where you need resources inside Azure only need to access the storage account. The restriction can also be applied to resources in the same resource group/subscription/tenant.

    <figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption><p>Resource based restrictions.</p></figcaption></figure>
* <mark style="color:blue;">**Private endpoint:**</mark> Using Private Link service, we can expose our storage endpoints without exposing to the Internet. [More information here.](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview)

#### 3. Different Endpoints

The following are different ways in which data inside the storage account can be accessed.

* <mark style="color:blue;">**Static Website:**</mark> This is typically for a plain HTML website (e.g. landing page).
* <mark style="color:blue;">**CDN Endpoints:**</mark> Azure Front door or Azure CDN can be used for exposing the files inside a specific container. `<custom-name>`.azurefd.net will be assigned when Azure front door will be selected and `<custom-name>`.azureedge.net will be assigned for Azure CDN.&#x20;
* <mark style="color:blue;">**Custom domain:**</mark> You can add a custom domain and expose data using the same.

#### 4. Misconfiguration leading to anonymous exposure:

Finally, the most probably way that data is exposed/adversaries can access data is when the data is misconfigured. More details are outlined in the next section.

## 💀 Attack Techniques

Below mentioned are few attack paths that I've observed in the wild. Please note that this isn't an exhaustive list and I intend to document many more attack paths in part-2 (that's planned to come out soon).

* <mark style="color:blue;">**Compromise of Ingress points (Identity or Access keys or Misconfiguration):**</mark> An adversary can simply compromise an identity (user account or service principal) and can compromise sensitive data that the compromised user has access to. How the user is compromised is out of the scope for the blog, but common techniques include Password spraying, info stealers, AITM phishing, etc.
* <mark style="color:blue;">**Misconfigured Storage account:**</mark> Storage account can be misconfigured to be allowed public access. Needless to say, this is particularly very dangerous. Check your code for any access point without SAS token which is in the format: `?sp=xxx&st=xxx&sig=xxx`. Below is an example of a harmless file present in github code without a SAS URL. While a file being exposed without a SAS isn't explicitly dangerous and might be completely intended, it's definitely something to look into.

<figure><img src="../../.gitbook/assets/image (18).png" alt=""><figcaption><p>Storage account without SAS</p></figcaption></figure>

* <mark style="color:blue;">**Rotate Key to cause DoS:**</mark> An adversary can simply rotate keys that are used to create SAS. Any downstream applications leveraging these keys to create signatures will break causing a potential denial of service. The rotation of account key would also remediate all the SAS tokens that are generated with that key. The reference for the action is below.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption><p>Rotation of keys</p></figcaption></figure>

* <mark style="color:blue;">**Leaked SAS token:**</mark> A SAS token is typically the defacto way of sharing access to objects inside a storage account. These SAS keys can have longer validity (spanning over years) and once created, there's no way to keep a track of it. Azure (as of today) doesn't provide a place for checking all issued SAS's and doesn't provide a way to revoke an individual SAS. The only way to remediate a SAS with a long expiry date is to reset the account key.&#x20;

<figure><img src="../../.gitbook/assets/image (20).png" alt=""><figcaption><p>Revoked Account key leading to SAS expiry.</p></figcaption></figure>

## 💂‍♂️Logging opportunities

Logging for activity related to Azure storage account can be enabled by using Azure diagnostic settings. In addition to that, I recommend enabling Azure activity log.

For the sake of this blog, all the logs are being forwarded to Log analytics workspace. However, the same can be forwarded to a storage account and subsequently forwarded to an SIEM. However, the detection logic would still remain the same except the query.&#x20;

For a storage account, there are 4 levels of diagnostic settings that can be enabled.

* Storage Account: Activity related to entire storage account, audit of properties, etc. will be covered here.
* Blob: Activity related to blob, access of data, etc., will be logged.
* Queue: Activity related to queue, access of data, etc., will be logged.
* Table: Activity related to table, access of data, etc., will be logged.
* File: Activity related to file share, access of data, etc., will be logged.

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption><p>Different types of logs that are available.</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption><p>To enable individual audit and other logs</p></figcaption></figure>

## 🦾Tracing of Activity

The operation is logged under `OperationName` and the following query can be used to check the operation. In addition, the authentication method will be available in `AuthenticationType` column.

```java
StorageBlobLogs
| where OperationName has_any("<operation-name>")
```

The following are the values that are majorly seen values in Operation Name field.&#x20;

* SetBlobStorageProperties - Change the properties of blob
* GetUserDelegationKey - Get the delegation key that's used for creating signature
* SetContainerProperties - Changes to properties of the container
* SetContainerACL - Changes to ACL using Rest API
* GetBlob - Download of an object
* DeleteBlob - Delete of a blob
* CopyBlob - Copying a blob to another blob
* DeleteContainer - Deletion of a container

The entire list of operation name can be found [here](https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api).

E.g. The following query can be used to check who accessed the blob. `ListBlobs` OperationName can be used for the same.

```java
StorageBlobLogs
| where OperationName has_any("ListBlobs")
```

{% hint style="info" %}
Generally, these events are very noisy and especially for blobs with multiple users using it. I'd suggest filtering a specific sensitive blob name or using anomaly detection mechanisms.
{% endhint %}

## 🔐Detections

The following are few detections that can be used.

* <mark style="color:blue;">**Detect Data exfiltration out of storage account:**</mark> This is one of the most disastrous things that can probably happen with a storage account. The following query can be used to detect data exfiltration out of a storage account. This leverages Azure metrics logs in storage account. If that setting (while enabling diagnostic settings) isn't enabled, the following query will not work.

<pre class="language-java" data-overflow="wrap"><code class="lang-java"><strong>//Threshold based 
</strong><strong>AzureMetrics
</strong>| where TimeGenerated > ago(1d)
| where MetricName == 'Egress'
| summarize TotalEgress = sum(Val2) by bin(TimeGenerated, 1h), ResourceId
| where TotalEgress > 100000
</code></pre>

* <mark style="color:blue;">**Detect mass deletion of data from a storage account:**</mark> The following query can be used to detect mass deletion of data from storage account. This query can be a little noisy if you use automation to make changes to a storage account (depending on your architecture, hence filter false +ves, before deploying).&#x20;

```java
StorageBlobLogs
| where Category == "StorageDelete" and OperationName == "DeleteBlob"
| where TimeGenerated > ago(1d)
| summarize count() by _ResourceId
| where count_ > 100 //change it according to your environment
```

* <mark style="color:blue;">**Compromised User accessing storage account settings:**</mark> By leveraging Entra ID's Risk detection features, we can check if a user is possibly compromised and if any user who is compromised, is accessing storage accounts, we can identify the same using the following query. Please note that there are other variants to the same query which can be achieved through SignIn logs table. It's also important to note that not all risky users are compromised users. However, they have to be taken care of. Additionally, the same data (risky users) can be used with StorageBlobLogs and other tables to identify additional adversarial activity.

```java
let RiskyUsersData = AADUserRiskEvents
|summarize by UserPrincipalName, IpAddress;
let RiskyCallers = RiskyUsersData | distinct UserPrincipalName;
let RiskyIPs = RiskyUsersData | distinct IpAddress;
AzureActivity
| where TimeGenerated >= ago(1d)
| extend clientIpAddress = parse_json(HTTPRequest)['clientIpAddress']
| where Caller has_any(RiskyCallers) and clientIpAddress has_any(RiskyIPs)
```

* <mark style="color:blue;">**Changes to diagnostic settings:**</mark> An adversary would want to remove diagnostic settings to impair defenses. The following query can be used to identify the same.

{% code overflow="wrap" %}
```java
AzureDiagnostics
| where OperationName == "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"
| where ResultType == "Success"
| where TimeGenerated >= ago(1d)
| project ResourceId, CallerIpAddress, CallerPrincipalName, TimeGenerated
```
{% endcode %}

## 👍Best Practices

* Don't enable Anonymous Access
* Use MFA for all sensitive accounts (Accounts with access to sensitive data).
* Enabling logging to log analytics or any SIEM of your choice.
* Perform RBAC analysis at regular intervals to check if the intended set of users only have access to storage accounts.
* Rotate keys used to sign SAS at regular intervals (e.g. 180 days).
* Don't create SAS tokens with very long validity.
* Check your code for SAS tokens, access keys and anonymous blob references.&#x20;
* Leverage resource isolation features using network and resource isolation features.&#x20;
* Unless there's a need to expose to the Internet (as a static website), don't expose to the Internet.
* If there's a requirement for your files to be exposed as a website, consider using static website or CDN or AFD instead of exposing the files over the Internet. These services perform caching for better performance.
* Inside Configuration of a storage account, you can restrict which storage accounts can copy data from your storage account. Unless required, select the option: "From storage accounts that have a private endpoint to the same virtual network" to avoid data exfiltration.
* If your budget supports, consider Microsoft defender for storage. Their offering is very competitive.

## 🤘Conclusion

I hope you enjoyed reading the blog. This is an evolving space and will change over time. I'll try to update as much as possible. If you find any discrepancy or have any feedback, please reach out to me. I'd be happy to take any feedback (critical or otherwise).&#x20;

It's not over yet. There will be more attack techniques, detections in part-2 and while I'm working towards a part-2 of this blog and if you have any feedback, please reach out to me using my contact details [here](../../).
