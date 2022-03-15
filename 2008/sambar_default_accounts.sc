if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80081" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_name( "Sambar Default Accounts" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Renaud Deraison" );
	script_family( "Remote file access" );
	script_dependencies( "gb_sambar_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sambar_server/detected" );
	script_tag( name: "solution", value: "Set a password for each account." );
	script_tag( name: "summary", value: "The Sambar web server comes with some default accounts.

  This script makes sure that all these accounts have a password set." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
valid = NULL;
useragent = http_get_user_agent();
host = http_host_name( port: port );
for user in make_list( "billy-bob",
	 "admin",
	 "anonymous" ) {
	content = NASLString( "RCpage=%2Fsysuser%2Fdocmgr%2Fbrowse.stm", "&onfailure=%2Fsysuser%2Fdocmgr%2Frelogin.htm", "&path=%2F&RCSsortby=name&RCSbrowse=%2Fsysuser%2Fdocmgr", "&RCuser=", user, "&RCpwd=" );
	req = NASLString( "POST /session/login HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/xml, text/html\\r\\n", "Accept-Language: us\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( content ), "\\r\\n\\r\\n", content );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res || IsMatchRegexp( res, "^HTTP/1\\.[01] 404" )){
		continue;
	}
	if(ContainsString( res, "Sambar Server Document Manager" )){
		valid += user + "\n";
	}
}
if(valid){
	if( ContainsString( valid, "admin" ) ){
		alert_admin = "Note that the privileged \"admin\" account is affected.\n";
	}
	else {
		alert_admin = "";
	}
	report = NASLString( "It is possible to log in as the following passwordless", "users in the remote Sambar web server :\n", valid, "\n", alert_admin, "An attacker may use this flaw to alter the content of this", "server." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

