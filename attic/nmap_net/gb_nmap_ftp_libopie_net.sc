if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104128" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_cve_id( "CVE-2010-1938" );
	script_bugtraq_id( 40403 );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Nmap NSE net: ftp-libopie" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://nmap.org/r/fbsd-sa-opie" );
	script_tag( name: "summary", value: "Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow), a vulnerability
discovered by Maksymilian Arciemowicz and Adam 'pi3' Zabrocki. See the referenced advisory. Be advised that, if launched against a vulnerable host, this script will crash the
FTPd." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

