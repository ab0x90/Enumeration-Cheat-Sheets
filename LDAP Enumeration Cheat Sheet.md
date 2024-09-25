# Using MMC to Enumerate Domain


MMC can be used to enumerate the domain from a non-domain joined machine (commando). This is not the most effective way for larger domains.

```cmd
runas /netonly /user:Domain_Name\Domain_USER mmc
```

Go to File > Add/Remove Snap-In
***image for snapin

If using from a system that is not domain joined, you will get an error that the specified domain does not exist or could not be contacted. Right click on the Root Domain folder and click "change domain".
***image for change domain

# Types of LDAP Authentication
1. **Simple Authentication:** This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a username and password create a BIND request to authenticate to the LDAP server.
2. **SASL Authentication:** The [Simple Authentication and Security Layer (SASL)](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) framework uses other authentication services, such as Kerberos, to bind to the `LDAP` server and then uses this authentication service (Kerberos in this example) to authenticate to `LDAP`. The `LDAP` server uses the `LDAP` protocol to send an `LDAP` message to the authorization service which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication. SASL can provide further security due to the separation of authentication methods from application protocols.


# LDAP Queries Using ADModule

```powershell
#simple LDAP query, can change to user, group etc.
Get-ADObject -LDAPFilter '(objectClass=computer)' | select name

#Search for disabled accounts
Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol

#Search for enabled accounts
Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol

#Search for a specific user using -eq
Get-ADUser -Filter {name -eq 'sally jones'}

#Search for machine names using -like
Get-ADComputer  -Filter "DNSHostName -like 'SQL*'"

#Find admin users
Get-ADGroup -Filter "adminCount -eq 1" | select Name

#Find admin users that do not require pre-auth
Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}

#Find all users that do not require pre-auth
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'}

#find enabled admin users with an SPN
Get-ADUser -Filter {adminCount -eq '1' -and Enabled -eq 'True'} -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl

#Find enabled users with information in their description
Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))' | select samaccountname,description

#Find enabled, trusted users
Get-ADUser -Properties * -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!userAccountControl:1.2.840.113556.1.4.803:=2))' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl


#Find enabled, trusted computers
Get-ADComputer -Properties * -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!userAccountControl:1.2.840.113556.1.4.803:=2))' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl

#Find admin users with blank passwords
Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl

#Find all, enabled users with blank passwords
Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select name,memberof | fl

#Find all groups a user is in, recursive search for nested groups
Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=domain,DC=local"' | select name  
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=domain,DC=local)' |select Name

#Count of all users in an OU
(Get-ADUser -SearchBase "OU=Employees,DC=domain,DC=local" -Filter *).count

#Find all DCs
Get-ADObject -LDAPFilter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' | select Name,ObjectGUID

#Find all servers (non-DCs) in the domain
 get-adobject -ldapfilter '(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' | select Name,ObjectClass,ObjectGUID

#Find certificate authorities and publishers
get-adobject -ldapfilter '(CN="Cert Publishers"*)'

#Find all OUs
get-adobject -ldapfilter '(objectCategory=organizationalUnit)'

#Find all containers
#Look for non-default AD containers.
get-adobject -ldapfilter '(objectCategory=container)'

#Find all unconstrained delegation
get-adobject -ldapfilter '(&(objectClass=User)(msDS-AllowedToDelegateTo=*))'

#Find RBCD
get-adobject -ldapfilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'

#Shadow Credentials
get-adobject -ldapfilter '(msDS-KeyCredentialLink=*)'

#Computer object with descriptions
get-adobject -ldapfilter '(&(objectCategory=computer)(description=*))'

#User accounts with SID History, may have access in another domain
get-adobject -ldapfilter '(&(objectCategory=Person)(objectClass=User)(sidHistory=*))'

#Generate list of user accounts
get-adobject -ldapfilter '(&(objectCategory=Person)(objectClass=User)(samaccountname=*))'

#Generate list of computer accounts
get-adobject -ldapfilter '(&(objectClass=Computer)(samaccountname=*))'
```


# Anonymous LDAP Bind
```sh
#check for anon bind  
ldapsearch -H ldap://10.129.1.207 -x -b "dc=domain,dc=local"  
  
#check for anon bind  
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality  
  
#pull all users  
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U  
  
#pull all computers  
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C
```


# LDAP Credentialed Enumeration using windapsearch/ldapsearch

```sh
python3 windapsearch.py --dc-ip 10.129.1.207 -u domain\\james.cross --da  
  
#unconstrained users  
python3 windapsearch.py --dc-ip 10.129.1.207 -d domain.local -u domain\\james.cross --unconstrained-users
```