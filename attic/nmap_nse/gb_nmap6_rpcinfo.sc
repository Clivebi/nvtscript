if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803504" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 18:59:53 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: rpcinfo" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Connects to portmapper and fetches a list of all registered programs.  It then prints out a table
including (for each program) the RPC program number, supported version numbers, port number and
protocol, and program name.

SYNTAX:

nfs.version:  number If set overrides the detected version of nfs

mount.version:  number If set overrides the detected version of mountd

rpc.protocol:  table If set overrides the preferred order in which
protocols are tested. (ie. 'tcp', 'udp')" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

