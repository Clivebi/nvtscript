if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104136" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Nmap NSE net: ms-sql-empty-password" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to authenticate using an empty password for the sysadmin (sa) account.

SYNTAX:

mssql.timeout:  How long to wait for SQL responses. This is a number
followed by 'ms' for milliseconds, 's' for seconds,
'm' for minutes, or 'h' for hours. Default:'30s'." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

