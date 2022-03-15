if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104007" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_cve_id( "CVE-2010-2965" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Nmap NSE net: wdb-version" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/362332" );
	script_tag( name: "summary", value: "Detects vulnerabilities and gathers information (such as version numbers and hardware support) from
VxWorks Wind DeBug agents.

Wind DeBug is a SunRPC-type service that is enabled by default on many devices that use the popular
VxWorks real-time embedded operating system. H.D. Moore of Metasploit has identified several
security vulnerabilities and design flaws with the service, including weakly-hashed passwords and
raw memory dumping.

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

