if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105536" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-11 12:25:49 +0100 (Thu, 11 Feb 2016)" );
	script_name( "Cisco Application Policy Infrastructure Controller Enterprise Module Detection" );
	script_tag( name: "summary", value: "This Script performs HTTP(s) based detection of Cisco Application Policy Infrastructure Controller Enterprise Module.
  When HTTP(s) credentials are given, the script is able to extract version and patch information from the application." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_add_preference( name: "APIC Username: ", value: "", type: "entry" );
	script_add_preference( name: "APIC Password: ", type: "password", value: "" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( port: port, item: "/" );
if(!ContainsString( buf, "<title>Home - APIC - Enterprise Module</title>" ) || !ContainsString( buf, "APIC-EM" )){
	exit( 0 );
}
set_kb_item( name: "cisco/apic_em/installed", value: TRUE );
user = script_get_preference( "APIC Username: " );
pass = script_get_preference( "APIC Password: " );
cpe = "cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module";
if(user && pass){
	login_credentials = TRUE;
	host = http_host_name( port: port );
	useragent = http_get_user_agent();
	data = "{\"username\":\"" + user + "\",\"password\":\"" + pass + "\"}";
	len = strlen( data );
	req = "POST /grapevine/api/auth/login HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: application/json, text/javascript, */*; q=0.01\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Accept-Encoding: identify\r\n" + "Content-Type: application/json; charset=UTF-8\r\n" + "token: undefined\r\n" + "X-Requested-With: XMLHttpRequest\r\n" + "Content-Length: " + len + "\r\n" + "Connection: close\r\n" + "\r\n" + data;
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "success" )){
		login_success = TRUE;
		_token = eregmatch( pattern: "\"token\": \"([^\"]+)\"", string: buf );
		if(!isnull( _token[1] )){
			token = _token[1];
		}
		if(token){
			req = "GET /grapevine/api/release/current HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: */*\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Accept-Encoding: identify\r\n" + "Content-Type: application/json; charset=UTF-8\r\n" + "token: " + token + "\r\n" + "X-Requested-With: XMLHttpRequest\r\n" + "Connection: close\r\n\r\n";
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(ContainsString( buf, "success" )){
				version = eregmatch( pattern: "APIC-EM apic-GA Release ([0-9.]+[^ ]+)", string: buf );
				if(!isnull( version[1] )){
					vers = version[1];
					cpe += ":" + vers;
					set_kb_item( name: "cisco/apic_em/version", value: vers );
				}
				js_data = split( buffer: buf, sep: "\"services\": {", keep: FALSE );
				if(!isnull( js_data[1] )){
					services = split( buffer: js_data[1], sep: ",", keep: FALSE );
					if(services){
						for s in services {
							s = ereg_replace( string: s, pattern: "[ \"}]", replace: "" );
							line += s + " ";
						}
						if(line){
							set_kb_item( name: "cisco/apic_em/installed_services", value: line );
						}
					}
				}
			}
		}
	}
}
report = "Detected Cisco Application Policy Infrastructure Controller Enterprise Module\n";
if(!vers && line){
	version = eregmatch( pattern: " version:([0-9.]+[^ ]+) ", string: line );
	if(!isnull( version[1] )){
		vers = version[1];
		cpe += ":" + vers;
		set_kb_item( name: "cisco/apic_em/version", value: vers );
	}
}
if( vers ) {
	report += "Version: " + vers + "\n";
}
else {
	if( login_credentials ) {
		if( login_success ) {
			extra_report = "\n\n** The scanner was able to login but failed to get the version **.\n\n";
		}
		else {
			extra_report = "\n\n** The scanner was not able to login using the given credentials **.\n\n";
		}
	}
	else {
		extra_report = "\n\n** No HTTP(s) credentials where given. Scanner was not able to extract version and patch information from the application. **\n\n";
	}
}
report += "CPE: " + cpe + "\n";
report += "Location: /";
if(extra_report){
	report += extra_report;
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( port: port, data: report );
exit( 0 );

