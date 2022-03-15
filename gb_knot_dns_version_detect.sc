if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806810" );
	script_version( "2021-04-13T12:30:37+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-13 12:30:37 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-01-04 13:14:29 +0530 (Mon, 04 Jan 2016)" );
	script_name( "KNOT DNS Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "dns_server_tcp.sc", "dns_server.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_tag( name: "summary", value: "Detection of installed version
  of Knot DNS Server.

  This script sends standard query and try to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
func getVersion( data, port, proto ){
	var data, port, proto, version, ver, cpe;
	if(!ContainsString( tolower( data ), "knot dns" )){
		return;
	}
	version = "unknown";
	ver = eregmatch( pattern: "Knot DNS ([0-9A-Z.-]+)", string: data, icase: TRUE );
	if(ver[1]){
		version = ver[1];
	}
	cpe = build_cpe( value: version, exp: "^([0-9/.]+)", base: "cpe:/a:knot:dns:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:knot:dns";
	}
	set_kb_item( name: "KnotDNS/version", value: version );
	set_kb_item( name: "KnotDNS/installed", value: TRUE );
	register_product( cpe: cpe, location: port + "/" + proto, port: port, proto: proto );
	log_message( data: build_detection_report( app: "KNOT DNS", version: version, install: port + "/" + proto, cpe: cpe, concluded: ver[0] ), port: port, proto: proto );
}
udp_Ports = get_kb_list( "DNS/udp/version_request" );
for port in udp_Ports {
	data = get_kb_item( "DNS/udp/version_request/" + port );
	if(!data){
		continue;
	}
	getVersion( data: data, port: port, proto: "udp" );
}
tcp_Ports = get_kb_list( "DNS/tcp/version_request" );
for port in tcp_Ports {
	data = get_kb_item( "DNS/tcp/version_request/" + port );
	if(!data){
		continue;
	}
	getVersion( data: data, port: port, proto: "tcp" );
}
exit( 0 );

