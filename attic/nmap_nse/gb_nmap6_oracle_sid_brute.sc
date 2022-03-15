if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803546" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:35 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: oracle-sid-brute" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "http://seclists.org/nmap-dev/2009/q4/645" );
	script_tag( name: "summary", value: "Guesses Oracle instance/SID names against the TNS-listener.

If the 'oraclesids' script argument is not used to specify an alternate file, the default
'oracle-sids' file will be used. License to use the 'oracle-sids' file was
granted by its author, Alexander Kornbrust (see references).

SYNTAX:

oraclesids:  A file containing SIDs to try." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

