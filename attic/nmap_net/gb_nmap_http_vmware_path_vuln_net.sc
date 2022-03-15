if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104150" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_cve_id( "CVE-2001-1013" );
	script_bugtraq_id( 3335 );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: http-vmware-path-vuln" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://fyrmassociates.com/tools.html" );
	script_tag( name: "summary", value: "Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server (CVE-2009-3733).

The vulnerability was originally released by Justin Morehouse and Tony Flick, who presented at
Shmoocon 2010 (see reference).

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-max-cache-size:  The maximum memory size (in bytes) of the cache." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

