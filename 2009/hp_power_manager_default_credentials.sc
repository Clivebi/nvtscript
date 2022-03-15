CPE = "cpe:/a:hp:power_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100350" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "HP Power Manager Management default credentials" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "hp_power_manager_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "hp_power_manager/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password for the user 'admin'." );
	script_tag( name: "summary", value: "The installed remote HP Power Manager has the default credentials 'admin' for
  username and password set." );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
variables = "HtmlOnly=true&Login=admin&Password=admin&loginButton=Submit%20Login";
host = http_host_name( port: port );
filename = dir + "/goform/formLogin";
req = NASLString( "POST ", filename, " HTTP/1.0\\r\\n", "Referer: http://", host, filename, "\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( variables ), "\\r\\n\\r\\n", variables );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(res && ContainsString( res, "top.location.href = '/Contents/index.asp';" )){
	report = http_report_vuln_url( port: port, url: filename );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

