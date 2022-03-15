if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114070" );
	script_version( "2021-02-25T16:05:56+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 16:05:56 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-02-13 14:52:10 +0100 (Wed, 13 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Beward IP Camera Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Beward IP cameras." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/profile";
res = http_get_cache( port: port, item: url );
if(IsMatchRegexp( res, "initProdNbr=\"([^\"]+)\";" ) && IsMatchRegexp( res, "BrandCopyright=\"Beward\\s*R&D\\s*Co.,\\s*Ltd.\\s*\";" )){
	version = "unknown";
	model = "unknown";
	mod = eregmatch( pattern: "initProdNbr=\"([^\"]+)\";", string: res );
	if(!isnull( mod[1] )){
		model = NASLString( mod[1] );
		set_kb_item( name: "beward/ip_camera/http/" + port + "/concluded", value: mod[0] );
	}
	set_kb_item( name: "beward/ip_camera/detected", value: TRUE );
	set_kb_item( name: "beward/ip_camera/http/detected", value: TRUE );
	set_kb_item( name: "beward/ip_camera/http/port", value: port );
	set_kb_item( name: "beward/ip_camera/http/" + port + "/detected", value: TRUE );
	set_kb_item( name: "beward/ip_camera/http/" + port + "/model", value: model );
	set_kb_item( name: "beward/ip_camera/http/" + port + "/version", value: version );
	set_kb_item( name: "beward/ip_camera/http/" + port + "/concludedurl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
}
exit( 0 );

