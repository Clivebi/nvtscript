if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100417" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-04-13T12:30:37+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 12:30:37 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Unbound DNS resolver Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "dns_server_tcp.sc", "dns_server.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_tag( name: "solution", value: "Set 'hide-version: yes' in unbound.conf." );
	script_tag( name: "summary", value: "The Unbound DNS resolver is running at this host.
  Unbound is a validating, recursive, and caching DNS resolver.

  The Unbound DNS resolver allow remote users to query for version and type information. The query of the
  CHAOS TXT record 'version.bind', will typically prompt the server to send the information back to the
  querying source." );
	script_xref( name: "URL", value: "https://nlnetlabs.nl/projects/unbound/about/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
func getVersion( data, port, proto ){
	var data, port, proto, version, ver, cpe;
	if(!ContainsString( tolower( data ), "unbound" )){
		return;
	}
	version = "unknown";
	ver = eregmatch( pattern: "unbound ([0-9.]+)", string: data, icase: TRUE );
	if(ver[1]){
		version = ver[1];
	}
	set_kb_item( name: "unbound/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9/.]+)", base: "cpe:/a:unbound:unbound:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:unbound:unbound";
	}
	register_product( cpe: cpe, location: port + "/" + proto, port: port, proto: proto );
	cpe = build_cpe( value: version, exp: "^([0-9/.]+)", base: "cpe:/a:nlnetlabs:unbound:" );
	if(!cpe){
		cpe = "cpe:/a:nlnetlabs:unbound";
	}
	register_product( cpe: cpe, location: port + "/" + proto, port: port, proto: proto );
	log_message( data: build_detection_report( app: "Unbound", version: version, install: port + "/" + proto, cpe: cpe, concluded: data ), port: port, proto: proto );
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

