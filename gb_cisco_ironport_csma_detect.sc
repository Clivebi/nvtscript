if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803753" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-09-03 18:58:59 +0530 (Tue, 03 Sep 2013)" );
	script_name( "Cisco Content Security Management Appliance Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  extract the version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
url = "/login";
headers = make_array( "Cookie", "sid=" + rand() );
req = http_get_req( port: port, url: url, add_headers: headers );
res = http_keepalive_send_recv( port: port, data: req );
if(( !ContainsString( res, "<title>Cisco IronPort" ) && !ContainsString( res, "SecurityManagementApp" ) ) && !IsMatchRegexp( res, "<title>\\s*Cisco\\s*Content Security Management( Virtual)? Appliance" )){
	url = "/euq-login";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !IsMatchRegexp( res, "Security Management( Virtual)? Appliance" ) || !ContainsString( res, "NG_SMA" )){
		exit( 0 );
	}
}
if(ContainsString( res, "Set-Cookie" )){
	cookie = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: res );
	if(!isnull( cookie[1] )){
		set_kb_item( name: "cisco_csm/http/cookie", value: TRUE );
		set_kb_item( name: "cisco_csm/http/" + port + "/cookie", value: cookie[1] );
	}
}
set_kb_item( name: "cisco_csm/detected", value: TRUE );
set_kb_item( name: "cisco_csm/http/detected", value: TRUE );
set_kb_item( name: "cisco_csm/http/port", value: port );
vers = eregmatch( pattern: "Version: (([0-9.]+)-?[0-9]+)", string: res );
if(isnull( vers[1] )){
	body = http_extract_body_from_response( data: res );
	if(body){
		vers = eregmatch( string: body, pattern: "v(([0-9.]{3,})-?[0-9]+)" );
	}
}
version = "unknown";
model = "unknown";
if(!isnull( vers[1] )){
	version = vers[1];
	concluded = "    " + vers[0];
}
mod = eregmatch( pattern: "ext_login_model\">Cisco ([^<]+)<", string: res );
if(!isnull( mod[1] )){
	model = mod[1];
	if(concluded){
		concluded += "\n";
	}
	concluded += "    " + mod[0];
}
set_kb_item( name: "cisco_csm/http/" + port + "/model", value: model );
set_kb_item( name: "cisco_csm/http/" + port + "/version", value: version );
if(concluded){
	set_kb_item( name: "cisco_csm/http/" + port + "/concluded", value: concluded );
}
exit( 0 );

