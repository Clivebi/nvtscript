if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813746" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-07 11:14:48 +0530 (Tue, 07 Aug 2018)" );
	script_name( "Harmonic NSG 9000 Devices Remote Detection" );
	script_tag( name: "summary", value: "Detection of presence of Harmonic NSG 9000
  Device.

  The script sends a HTTP GET connection request to the server and attempts
  to determine if the remote host runs Harmonic NSG 9000 Device from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.harmonicinc.com/products/product-detail/nsg-9000-40g" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
nsgPort = http_get_port( default: 80 );
banner = http_get_remote_headers( port: nsgPort );
if(!banner){
	exit( 0 );
}
if(IsMatchRegexp( banner, "^HTTP/1\\.[01] 401" ) && ContainsString( banner, "WWW-Authenticate: Basic realm=\"NSG9000\"" )){
	version = "unknown";
	install = nsgPort + "/tcp";
	set_kb_item( name: "nsg9000/detected", value: TRUE );
	set_kb_item( name: "nsgPort/http/port", value: nsgPort );
	cpe = "cpe:/h:harmonic:nsg_9000";
	register_product( cpe: cpe, location: install, port: nsgPort, service: "www" );
	log_message( data: build_detection_report( app: "Harmonic NSG 9000 Device", version: version, install: install, cpe: cpe, concluded: version ), port: nsgPort );
}
exit( 0 );

