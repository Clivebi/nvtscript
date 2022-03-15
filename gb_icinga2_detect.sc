if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113120" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-01 13:53:44 +0100 (Thu, 01 Mar 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Icinga 2 Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 5665 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks for the presence and version of Icinga 2 on the target host
  (Providing Icinga2 API Credentials can lead to better results)." );
	script_add_preference( name: "API Username", value: "", type: "entry" );
	script_add_preference( name: "API Password", value: "", type: "password" );
	script_xref( name: "URL", value: "https://www.icinga.com/products/icinga-2/" );
	script_xref( name: "URL", value: "https://www.icinga.com/docs/icinga2/latest/doc/12-icinga2-api/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 5665 );
banner = http_get_remote_headers( port: port );
detected = FALSE;
if(ContainsString( banner, "erver: Icinga" ) || ContainsString( banner, "Basic realm=\"Icinga 2\"" )){
	install = "/";
	version = "unknown";
	detected = TRUE;
	vers = eregmatch( string: banner, pattern: "Icinga/r?([0-9.-]+)" );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
}
if(detected && version == "unknown"){
	user = script_get_preference( "API Username" );
	pass = script_get_preference( "API Password" );
	if( !user && !pass ){
		extra = "Incinga 2 Detected but version unknown. Providing API credentials to this NVT might allow to gather the version.";
	}
	else {
		if( !user && pass ){
			log_message( data: "Password provided but Username is missing.", port: port );
		}
		else {
			if( user && !pass ){
				log_message( data: "Username provided but Password is missing.", port: port );
			}
			else {
				if(user && pass){
					url = "/v1/status/IcingaApplication";
					add_headers = make_array( "Authorization", "Basic " + base64( str: user + ":" + pass ) );
					req = http_get_req( port: port, url: url, add_headers: add_headers, accept_header: "*/*" );
					res = http_keepalive_send_recv( port: port, data: req );
					if( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "{\"results\":" ) ){
						vers = eregmatch( string: res, pattern: "\"version\":\"r?([0-9.-]+)\"" );
						if(!isnull( vers[1] )){
							version = vers[1];
							conclUrl = url;
						}
					}
					else {
						log_message( data: "Username and Password provided but login to the API failed with the following response:\n\n" + res, port: port );
					}
				}
			}
		}
	}
}
if(!detected){
	exit( 0 );
}
set_kb_item( name: "icinga2/detected", value: TRUE );
register_and_report_cpe( app: "Icinga 2", ver: version, insloc: install, concluded: vers[0], base: "cpe:/a:icinga:icinga2:", expr: "([r0-9.-]+)", conclUrl: conclUrl, regPort: port, extra: extra );
exit( 0 );

