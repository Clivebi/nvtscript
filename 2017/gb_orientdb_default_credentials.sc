CPE = "cpe:/a:orientdb:orientdb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112080" );
	script_version( "2020-05-08T11:13:33+0000" );
	script_name( "OrientDB Server Default Credentials" );
	script_tag( name: "last_modification", value: "2020-05-08 11:13:33 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2017-10-13 08:49:15 +0200 (Fri, 13 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_orientdb_server_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 2480 );
	script_mandatory_keys( "OrientDB/auth_required" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the passwords." );
	script_tag( name: "summary", value: "OrientDB is prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to sensitive information." );
	script_tag( name: "insight", value: "By convention, each time you create a new database OrientDB creates three default users (admin, writer, reader).
  The passwords for these users are the same as the usernames. That is, by default the admin user has a password of admin." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
credentials = make_list( "admin:admin",
	 "writer:writer",
	 "reader:reader" );
vuln = FALSE;
report = "It was possible to login into the OrientDB Server at: ";
host = http_host_name( dont_add_port: TRUE );
authRequireUrls = get_kb_list( "www/" + host + "/" + port + "/OrientDB/auth_required" );
if(isnull( authRequireUrls )){
	exit( 0 );
}
authRequireUrls = sort( authRequireUrls );
for url in authRequireUrls {
	for credential in credentials {
		user_pass = split( buffer: credential, sep: ":", keep: FALSE );
		user = chomp( user_pass[0] );
		pass = chomp( user_pass[1] );
		userpass = NASLString( user, ":", pass );
		userpass64 = base64( str: userpass );
		req = http_get_req( port: port, url: url, add_headers: make_array( "Authorization", "Basic " + userpass64), accept_headers: "application/json, text/plain, */*" );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "Server: OrientDB Server" ) || ContainsString( res, "{\"server\":{\"version\":" ) )){
			report += "\n\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " using user \"" + user + "\" with password \"" + pass;
			vuln = TRUE;
		}
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

