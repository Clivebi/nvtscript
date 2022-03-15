if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100208" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-04-13T12:30:37+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 12:30:37 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Name Server Daemon (NSD) Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "dns_server_tcp.sc", "dns_server.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_xref( name: "URL", value: "http://www.nlnetlabs.nl/projects/nsd/" );
	script_tag( name: "solution", value: "Set 'hide-version: yes' in nsd.conf." );
	script_tag( name: "summary", value: "The Name Server Daemon is running at this host.
  NSD is an authoritative only, high performance, simple and open source name
  server.

  The NSD allow remote users to query for version and type
  information. The query of the CHAOS TXT record 'version.bind', will
  typically prompt the server to send the information back to the
  querying source." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
func getVersion( data, port, proto ){
	var data, port, proto, version, ver, cpe;
	if(!ContainsString( tolower( data ), "nsd" )){
		return;
	}
	version = "unknown";
	ver = eregmatch( pattern: "NSD ([0-9.]+)", string: data, icase: TRUE );
	if(ver[1]){
		version = ver[1];
	}
	set_kb_item( name: "nsd/version", value: version );
	set_kb_item( name: "nsd/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nlnetlabs:nsd:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:nlnetlabs:nsd";
	}
	register_product( cpe: cpe, location: port + "/" + proto, port: port, proto: proto );
	log_message( data: build_detection_report( app: "NSD", version: version, install: port + "/" + proto, cpe: cpe, concluded: data ), port: port, proto: proto );
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

