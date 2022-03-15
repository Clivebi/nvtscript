if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140887" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-27 08:53:26 +0700 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "etcd Detection" );
	script_tag( name: "summary", value: "Detection of etcd.

The script sends a connection request to the server and attempts to detect etcd and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2379 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://coreos.com/etcd/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 2379 );
url = "/version";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "\"etcdserver\":" )){
	version = "unknown";
	vers = eregmatch( pattern: "\"etcdserver\":\"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	req = http_get( port: port, item: "/v2/stats/self" );
	res = http_keepalive_send_recv( port: port, data: req );
	data = eregmatch( pattern: "\"name\":\"([^\"]+)", string: res );
	if(!isnull( data[1] )){
		extra += "  Name:    " + data[1] + "\n";
	}
	data = eregmatch( pattern: "\"uptime\":\"([^\"]+)", string: res );
	if(!isnull( data[1] )){
		extra += "  Uptime:  " + data[1];
	}
	set_kb_item( name: "etcd/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:etcd:etcd:" );
	if(!cpe){
		cpe = "cpe:/a:etcd:etcd";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "etcd", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: url, extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

