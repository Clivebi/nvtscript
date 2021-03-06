if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141744" );
	script_version( "$Revision: 12895 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-28 14:53:10 +0100 (Fri, 28 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2018-12-03 13:14:07 +0700 (Mon, 03 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "D-Link Central WiFiManager Software Controller Detection Consolidation" );
	script_tag( name: "summary", value: "The script reports a detected D-Link Central WiFiManager Software Controller
including the version number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_dlink_wifimanger_detect.sc", "gb_dlink_wifimanger_detect_win.sc" );
	script_mandatory_keys( "dlink_central_wifimanager/detected" );
	script_xref( name: "URL", value: "http://us.dlink.com/products/business-solutions/central-wifimanager-software-controller/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "dlink_central_wifimanager/detected" )){
	exit( 0 );
}
version = get_kb_item( "dlink_central_wifimanager/win/version" );
if(!version){
	version = "unknown";
}
cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:d-link:central_wifimanager:" );
if(!cpe){
	cpe = "cpe:/a:d-link:central_wifimanager";
}
if(http_ports = get_kb_list( "dlink_central_wifimanager/http/port" )){
	if(!isnull( http_ports )){
		extra += "\nRemote Detection over HTTP(s):\n";
	}
	for port in http_ports {
		extra += "   Port:   " + port + "\n";
		register_product( cpe: cpe, location: "/", port: port, service: "www" );
	}
}
if(path = get_kb_item( "dlink_central_wifimanager/win/path" )){
	extra += "Local Detection on Windows:\n";
	extra += "   Path:   " + path + "\n";
	register_product( cpe: cpe, location: path, port: 0, service: "smb-login" );
}
report = build_detection_report( app: "D-Link Central WiFiManager Software Controller", version: version, cpe: cpe, extra: extra );
log_message( port: 0, data: report );
exit( 0 );

