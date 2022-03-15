if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104117" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE net: oracle-sid-brute" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://seclists.org/nmap-dev/2009/q4/645" );
	script_tag( name: "summary", value: "Guesses Oracle instance/SID names against the TNS-listener.

If the 'oraclesids' script argument is not used to specify an alternate file, the default
'oracle-sids' file will be used. License to use the 'oracle-sids' file was
granted by its author, Alexander Kornbrust (see reference).

SYNTAX:

oraclesids:  A file containing SIDs to try." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

