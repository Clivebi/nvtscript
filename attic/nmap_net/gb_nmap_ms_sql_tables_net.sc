if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104097" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: ms-sql-tables" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Queries Microsoft SQL Server (ms-sql) for a list of tables per database.

The sysdatabase table should be accessible by more or less everyone The script attempts to use the
sa account over any other if it has the password in the registry. If not the first account in the
registry is used.

Once we have a list of databases we iterate over it and attempt to extract table names. In order for
this to succeed we need to have either sysadmin privileges or an account with access to the db. So,
each database we successfully enumerate tables from we mark as finished, then iterate over known
user accounts until either we have exhausted the users or found all tables in all the databases.

Tables installed by default are excluded.

SYNTAX:

mssql-tables.maxdb:  Limits the amount of databases that are
processed and returned (default 5). If set to zero or less
all databases are processed.

mssql.timeout:  How long to wait for SQL responses. This is a number
followed by 'ms' for milliseconds, 's' for seconds,
'm' for minutes, or 'h' for hours. Default:
'30s'.

mssql.password:  specifies the password to use to connect to
the server. This option overrides any accounts found by
the 'ms-sql-brute' and 'ms-sql-empty-password' scripts.

mssql.username:  specifies the username to use to connect to
the server. This option overrides any accounts found by
the 'ms-sql-brute' and 'ms-sql-empty-password' scripts.

mssql-tables.keywords:  If set shows only tables or columns matching
the keywords

mssql-tables.maxtables:  Limits the amount of tables returned
(default 5). If set to zero or less all tables are returned." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

