# Brute_Ratel

DNS Over HTTPS

Alongside the default HTTPS connections, Badger's DNS over HTTPS provides usability of newly bought domains without the the need of domain fronting or redirector, all the while providing a backup option to be able to switch to other HTTPS profiles on the fly
Feature Additions:Ratel Server/Badger

LDAP Sentinel

This release brings in support for sleep and jitter for LDAP Sentinel with the ‘sentinel_sleep’ command. Using this, operators can provide an interval between every single LDAP request to the Domain Controller. Unlike previous releases, this version of LDAP Sentinel supports SASL authentication with a fallback mechanism to the default kerberos authentication. The SASL authentication consists of encrypted messages inside the LDAP “bind” requests and responses. The “bind” request contains the distinguished name of the directory object that Badger wishes to authenticate as either with an impersonated token or directly. This feature was added to support forced Certificate SASL authentication within some environments. Interestingly, this also provides better evasion against network based IDS which build detections against known LDAP queries from unencrypted data or by tracking multiple LDAP queries originating from one source and then tagging it as an anomaly. Due to the encrypted nature of the SASL authentication, it becomes difficult for various detection systems which do not handle SASL. Apart from these changes, LDAP Sentinel also supports attribute filtering. An operator can now provide multiple attribute filters within LDAP filters to limit search output to requested attributes. The below example shows attribute filters (name, distinguishedName, lastlogon and objectSid) added to the LDAP query to search user objects.
