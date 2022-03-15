if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100432" );
	script_version( "2021-04-13T12:30:37+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 12:30:37 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-01-07 12:29:25 +0100 (Thu, 07 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "PowerDNS (Authoritative Server and Recursor) Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "dns_server_tcp.sc", "dns_server.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_xref( name: "URL", value: "http://www.powerdns.com/" );
	script_tag( name: "summary", value: "Detection of PowerDNS (Authoritative Server and Recursor)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
func getVersion( data, port, proto ){
	var data, port, proto, version, ver, cpe;
	if(!ContainsString( tolower( data ), "powerdns" )){
		return;
	}
	version = "unknown";
	ver = eregmatch( pattern: "PowerDNS [a-zA-Z ]*([0-9.]+)", string: data, icase: TRUE );
	if(ver[1]){
		version = ver[1];
	}
	set_kb_item( name: "powerdns/recursor_or_authoritative_server/installed", value: TRUE );
	if( ContainsString( ver[0], "Recursor" ) ){
		type = "Recursor";
		set_kb_item( name: "powerdns/recursor/installed", value: TRUE );
		set_kb_item( name: "powerdns/recursor/version", value: version );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:powerdns:recursor:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:powerdns:recursor";
		}
	}
	else {
		type = "Authoritative Server";
		set_kb_item( name: "powerdns/authoritative_server/installed", value: TRUE );
		set_kb_item( name: "powerdns/authoritative_server/version", value: version );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:powerdns:authoritative_server:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:powerdns:authoritative_server";
		}
	}
	register_product( cpe: cpe, location: port + "/" + proto, port: port, proto: proto );
	log_message( data: build_detection_report( app: "PowerDNS " + type, version: version, install: port + "/" + proto, cpe: cpe, concluded: ver[0] ), port: port, proto: proto );
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

