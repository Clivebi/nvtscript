if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112773" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-30 13:22:14 +0000 (Tue, 30 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SATO Printer Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of SATO printers." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/WebConfig/";
buf = http_get_cache( port: port, item: url );
if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "<title>SATO Printer Setup</title>" )){
	set_kb_item( name: "sato_printer/detected", value: TRUE );
	set_kb_item( name: "sato_printer/http/detected", value: TRUE );
	set_kb_item( name: "sato_printer/http/port", value: port );
	url = "/rest/info";
	buf = http_get_cache( item: url, port: port );
	if(buf && ContainsString( buf, "printCount" ) && ContainsString( buf, "model" )){
		mod = eregmatch( pattern: "\"model\":\"([^\"]+)\",", string: buf );
		if(!isnull( mod[1] )){
			set_kb_item( name: "sato_printer/http/" + port + "/model", value: mod[1] );
		}
		vers = eregmatch( pattern: "\"system\":.+\"version\":\"([^\"]+)\"", string: buf );
		if(!isnull( vers[1] )){
			set_kb_item( name: "sato_printer/http/" + port + "/fw_version", value: vers[1] );
			set_kb_item( name: "sato_printer/http/" + port + "/concluded", value: vers[0] );
			set_kb_item( name: "sato_printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		}
		mac = eregmatch( pattern: "\"MAC\":\"([^\"]+)\"", string: buf );
		if(!isnull( mac[1] )){
			mac = tolower( mac[1] );
			set_kb_item( name: "sato_printer/http/" + port + "/mac", value: mac );
			register_host_detail( name: "MAC", value: mac, desc: "gb_sato_printer_http_detect.nasl" );
			replace_kb_item( name: "Host/mac_address", value: mac );
		}
		exit( 0 );
	}
}
exit( 0 );

