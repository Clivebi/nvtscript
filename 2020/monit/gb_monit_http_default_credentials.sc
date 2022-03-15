CPE = "cpe:/a:tildeslash:monit";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108738" );
	script_version( "2020-04-06T07:47:48+0000" );
	script_tag( name: "last_modification", value: "2020-04-06 07:47:48 +0000 (Mon, 06 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-06 06:26:03 +0000 (Mon, 06 Apr 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Monit Default Credentials (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_monit_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080, 8181 );
	script_mandatory_keys( "monit/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://bitbucket.org/tildeslash/monit/issues/881/configuration-file-with-default-username" );
	script_tag( name: "summary", value: "Monit use the default credentials in a configuration file." );
	script_tag( name: "vuldetect", value: "Tries to login using default credentials: 'admin:monit'." );
	script_tag( name: "solution", value: "Change the default credentials." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/" );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 401" ) || !IsMatchRegexp( res, "WWW-Authenticate\\s*:\\s*Basic realm=\"monit\"" )){
	exit( 0 );
}
username = "admin";
password = "monit";
req = http_get_req( port: port, url: "/", add_headers: make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) ) );
res = http_keepalive_send_recv( port: port, data: req );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 99 );
}
if(ContainsString( res, "<title>Monit: " )){
	report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

