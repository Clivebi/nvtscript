if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108567" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-25 08:00:03 +0000 (Thu, 25 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "TrendMicro TippingPoint Security Management System (SMS) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the remote host and attempts
  to detect the presence of a TrendMicro TippingPoint Security Management System (SMS)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/", port: port );
if(ContainsString( buf, "<title>TippingPoint Security Management System</title>" )){
	version = "unknown";
	url = "/dashboard/api/v1/common_info";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	vers_num = eregmatch( pattern: "\"version_number\":\"([^\"]+)\"", string: buf );
	if(vers_num[1]){
		version = vers_num[1];
		set_kb_item( name: "tippingpoint/sms/http/" + port + "/concluded", value: vers_num[0] );
		set_kb_item( name: "tippingpoint/sms/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
	set_kb_item( name: "tippingpoint/sms/http/" + port + "/version", value: version );
	set_kb_item( name: "tippingpoint/sms/detected", value: TRUE );
	set_kb_item( name: "tippingpoint/sms/http/detected", value: TRUE );
	set_kb_item( name: "tippingpoint/sms/http/port", value: port );
}
exit( 0 );

