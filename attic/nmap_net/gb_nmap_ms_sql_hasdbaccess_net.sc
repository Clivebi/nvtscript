if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104086" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: ms-sql-hasdbaccess" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Queries Microsoft SQL Server (ms-sql) for a list of databases a user has access to.

The script needs an account with the sysadmin server role to work. It needs to be fed credentials
through the script arguments or from the scripts 'mssql-brute' or 'mssql-empty-
password'.

When run, the script iterates over the credentials and attempts to run the command until either all
credentials are exhausted or until the command is executed.

SYNTAX:

mssql-hasdbaccess.limit:  limits the amount of databases per-user
that are returned (default 5). If set to zero or less all
databases the user has access to are returned.

mssql.password:  specifies the password to use to connect to
the server. This option overrides any accounts found by
the 'ms-sql-brute' and 'ms-sql-empty-password' scripts.

mssql.username:  specifies the username to use to connect to
the server. This option overrides any accounts found by
the 'mssql-brute' and 'mssql-empty-password' scripts.

mssql.timeout:  How long to wait for SQL responses. This is a number
followed by 'ms' for milliseconds, 's' for seconds,
'm' for minutes, or 'h' for hours. Default:
'30s'." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

