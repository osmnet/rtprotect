# IPv4 Route Protect

## Introduction

IPv4 Route Protect is a Windows service that "protects" an IPv4 route by forcing it to its original gateway with the narrowest netmask. For instance, protecting route to 8.8.8.8 on a host where the route to 8.8.8.8 is the default route via gateway 192.168.1.1, means creating the route 8.8.8.8/32 via 192.168.1.1.

## Installation

Protecting an IPv4 route this way on Windows requires having administrative privileges.

IPv4 Route Protect can be installed as a service by running cmd.exe as an administrator and using the following command:
```
sc create "IPv4 Route Protect" binPath=<Full path to rtprotect.exe>
```

IPv4 Route Protect service allows programs without administrative privileges to protect IPv4 routes. The only requirement for a process to be allowed is to have at least one of its modules (EXE or DLL) listed in IPv4 Route Protect configuration with correct hash.

## Building

To build rtprotect.exe, simply open a Visual C++ command line environment and use the following command:
```
cl /Ox rtprotect.cpp
```

## Example

The provided client example in rtprotectclient.cpp shows a very basic usage of IPv4 Route Protect service.

Compile it by opening a Visual C++ command environment and using the following command:
```
cl /Ox rtprotectclient.cpp
```

To get the resulting binary hash needed for IPv4 Route Protect configuration, run the following command line:
```
certutil -hashfile rtprotectclient.exe SHA256
```

Now create the following registry String Value:
```
HKEY_LOCAL_MACHINE\SOFTWARE\BMV\Authorized\rtprotectclient.exe = <SHA256 Value>
```

Note: rtprotect.exe needs to be restarted to take new registry configuration into account.

