if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803522" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:11 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-enum-domains" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Attempts to enumerate domains on a system, along with their policies. This generally requires
credentials, except against Windows 2000. In addition to the actual domain, the 'Builtin'  domain is
generally displayed. Windows returns this in the list of domains, but its policies  don't appear to
be used anywhere.

Much of the information provided is useful to a penetration tester, because it tells the tester what
types of policies to expect. For example, if passwords have a minimum length of 8, the tester can
trim his database to match. If the minimum length is 14, the tester will probably start looking for
sticky notes on people's monitors.

Another useful piece of information is the password lockouts. A penetration tester often wants to
know whether or not there's a risk of negatively impacting a network, and this will  indicate it.
The SID is displayed, which may be useful in other tools. The users are listed, which uses
different functions than 'smb-enum-users.nse' (though likely won't  get different
results), and the date and time the domain was created may give some insight into its history.

After the initial 'bind' to SAMR, the sequence of calls is:

  - 'Connect4': get a connect_handle

  - 'EnumDomains': get a list of the domains (stop here if you just want the names).

  - 'QueryDomain': get the SID for the domain.

  - 'OpenDomain': get a handle for each domain.

  - 'QueryDomainInfo2': get the domain information.

  - 'QueryDomainUsers': get a list of the users in the domain.

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

