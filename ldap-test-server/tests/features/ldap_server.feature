Feature: Writing tests scenarios with short living LDAP server

  It's common for bigger systems to synchronize with LDAP server for users, groups or accounts lists.
  This crate allow starting isolated LDAP server (openldap) in temporary directory and on a free TCP port,
  so developers can use it to creating automated tests.

  Application - tested code
  LDAP Server - temporary LDAP server started on random port
  LDIF - LDAP Data Interchange Format, format used for updating LDAP server (like SQL for postgres).

  Rule: Application can login to LDAP server
    Background:
      Given Created LDAP database
      And LDAP database initialized with empty Organizational Unit (ou) named 'people'
      And LDAP server is started

    Scenario: Applications successfully login with root dn user
      When Application tries to login to LDAP server
      Then Successfully logged

    Scenario: Applications failed to login with invalid password
      When Application simple binds to server with invalid password
      Then Got error 'invalidCredentials'

  Rule: Application can add schema server
    Background:
      Given Created LDAP database
      And LDAP database initialized with empty Organizational Unit (ou) named 'people'

    Scenario: Application can add Active Directory compatibility layer for attribute sAMAccountName
      When Application adds LDIF to LDAP database with AD compatibility layer
      Then Application can add person with filled sAMAccountName attribute

  Rule: Application can modify LDAP database while LDAP is running
    Background:
      Given Created LDAP database
      And LDAP database initialized with empty Organizational Unit (ou) named 'people'
      And LDAP server is started
      Given Application added person 'mk' to OU 'people' with LDIF
      Given Application added person 'mpa' to OU 'people' with LDIF

    Scenario: Applications can add LDAP server with LDIF
      Given Application added person 'ru' to OU 'people' with LDIF
      When Application queries LDAP server with '(objectClass=inetorgperson)'
      Then There is 3 result(s)

    Scenario: Applications can modify LDAP server with LDIF
      Given Application updated person 'mk' in OU 'people' with displayName 'kaka' with LDIF
      When Application queries LDAP server with '(&(objectClass=inetorgperson)(displayName=kaka))'
      Then There is 1 result(s)

    Scenario: Applications can delete LDAP server with LDIF
      Given Application deleted person 'mk' in OU 'people' with LDIF
      When Application queries LDAP server with '(objectClass=inetorgperson)'
      Then There is 1 result(s)
