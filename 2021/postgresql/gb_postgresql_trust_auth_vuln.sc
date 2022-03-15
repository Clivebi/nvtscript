CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145872" );
	script_version( "2021-05-03T06:24:36+0000" );
	script_tag( name: "last_modification", value: "2021-05-03 06:24:36 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-30 08:13:40 +0000 (Fri, 30 Apr 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "PostgreSQL Trust Authentication Enabled" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "postgresql_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/postgresql", 5432 );
	script_mandatory_keys( "postgresql/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Trust Authentication mode is enabled in PostgreSQL." );
	script_tag( name: "vuldetect", value: "Tries to access PostgreSQL without authentication and checks
  the response." );
	script_tag( name: "insight", value: "The PostgreSQL server is running in 'trust mode'. This enables
  anyone who can connect to the server to access the database." );
	script_tag( name: "impact", value: "An unauthenticated user may access the underlying database and
  read/alter it (e.g. adding a new superuser account)." );
	script_tag( name: "solution", value: "Choose another authentication method which enables secure
  authentication." );
	script_xref( name: "URL", value: "https://www.postgresql.org/docs/9.2/auth-methods.html#AUTH-TRUST" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("postgresql.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "postgresql" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
user = "postgres";
password = "";
db = "postgres";
if(postgresql_login( socket: soc, user: user, password: password, db: db )){
	close( soc );
	report = "It was possible to authenticate to the PostgreSQL database with the following credentials:\n\n" + "Username:  " + user + "\nPassword:  (no password)\nDatabase:  " + db;
	security_message( port: port, data: report );
	exit( 0 );
}
close( soc );
exit( 99 );

