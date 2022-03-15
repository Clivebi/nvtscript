if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104063" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: ipidseq" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Classifies a host's IP ID sequence (test for susceptibility to idle scan).

Sends six probes to obtain IP IDs from the target and classifies them similarly to Nmap's method.
This is useful for finding suitable zombies for Nmap's idle scan ('-sI') as Nmap itself
doesn't provide a way to scan for these hosts.

SYNTAX:

probeport:  Set destination port to probe" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

