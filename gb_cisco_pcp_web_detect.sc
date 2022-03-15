if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105548" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-16 10:35:13 +0100 (Tue, 16 Feb 2016)" );
	script_name( "Cisco Prime Collaboration Provisioning Web Detection" );
	script_tag( name: "summary", value: "This Script performs HTTP(s) based detection of the Cisco Prime Collaboration Provisioning Web Interface" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( buf, "HTTP/1.. 302" ) && ContainsString( buf, "/cupm/Login" )){
	cpe = "cpe:/a:cisco:prime_collaboration_provisioning";
	vers = "unknown";
	url = "/dfcweb/lib/cupm/nls/applicationproperties.js";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( buf, "Cisco Prime Collaboration" )){
		exit( 0 );
	}
	set_kb_item( name: "cisco/cupm/http/version", value: vers );
	set_kb_item( name: "cisco/cupm/http/port", value: port );
	version = eregmatch( pattern: "file_version: \"Version ([^\"]+)\",", string: buf );
	if(!isnull( version[1] )){
		vers = version[1];
		cpe += ":" + vers;
	}
	report = "The Cisco Prime Collaboration Provisioning Web Interface is running at this port.\n" + "Version: " + vers + "\n" + "CPE: " + cpe + "\n";
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

