if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113242" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-07 10:33:33 +0200 (Tue, 07 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Autonomic Controls Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection for Autonomic Controls devices using HTTP." );
	script_xref( name: "URL", value: "http://www.autonomic-controls.com/products/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && IsMatchRegexp( banner, "Autonomic Controls" )){
	set_kb_item( name: "autonomic_controls/detected", value: TRUE );
	set_kb_item( name: "autonomic_controls/http/port", value: port );
	ver = eregmatch( string: banner, pattern: "Autonomic Controls/([0-9.]+)", icase: TRUE );
	if(!isnull( ver[1] )){
		set_kb_item( name: "autonomic_controls/http/version", value: ver[1] );
		set_kb_item( name: "autonomic_controls/http/concluded", value: ver[0] );
	}
}
exit( 0 );

