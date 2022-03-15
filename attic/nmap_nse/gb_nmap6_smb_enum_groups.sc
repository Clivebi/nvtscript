if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803557" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:46 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-enum-groups" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Obtains a list of groups from the remote Windows system, as well as a list of the group's users.
This works similarly to 'enum.exe' with the '/G' switch.

The following MSRPC functions in SAMR are used to find a list of groups and the RIDs of their users.
Keep in mind that MSRPC refers to groups as 'Aliases'.

  - 'Bind': bind to the SAMR service.

  - 'Connect4': get a connect_handle.

  - 'EnumDomains': get a list of the domains.

  - 'LookupDomain': get the RID of the domains.

  - 'OpenDomain': get a handle for each domain.

  - 'EnumDomainAliases': get the list of groups in the domain.

  - 'OpenAlias': get a handle to each group.

  - 'GetMembersInAlias': get the RIDs of the members in the groups.

  - 'Close': close the alias handle.

  - 'Close': close the domain handle.

  - 'Close': close the connect handle.

Once the RIDs have been determined, the

  - 'Bind': bind to the LSA service.

  - 'OpenPolicy2': get a policy handle.

  - 'LookupSids2': convert SIDs to usernames.

I (Ron Bowes) originally looked into the possibility of using the SAMR function
'LookupRids2'  to convert RIDs to usernames, but the function seemed to return a fault no
matter what I tried. Since  enum.exe also switches to LSA to convert RIDs to usernames, I figured
they had the same issue and I do  the same thing.

SYNTAX:

smbbasic:     Forces the authentication to use basic security, as opposed to 'extended security'.
Against most modern systems, extended security should work, but there may be cases
where you want to force basic. There's a chance that you'll get better results for
enumerating users if you turn on basic authentication.

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.

smbsign:       Controls whether or not server signatures are checked in SMB packets. By default, on Windows,
server signatures aren't enabled or required. By default, this library will always sign
packets if it knows how, and will check signatures if the server says to. Possible values are:

  - 'force':      Always check server signatures, even if server says it doesn't support them (will
probably fail, but is technically more secure).

  - 'negotiate': [default] Use signatures if server supports them.

  - 'ignore':    Never check server signatures. Not recommended.

  - 'disable':   Don't send signatures, at all, and don't check the server's. not recommended.
More information on signatures can be found in 'smbauth.lua'.

randomseed:    Set to a value to change the filenames/service names that are randomly generated." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

