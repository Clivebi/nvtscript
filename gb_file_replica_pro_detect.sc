if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806688" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-01 14:45:33 +0530 (Tue, 01 Mar 2016)" );
	script_name( "File Replication Pro Remote Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 9100 );
	script_tag( name: "summary", value: "Detects the installed version of
  File Replication Pro.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9100 );
rcvRes = http_get_cache( item: "/Login.jsp", port: port );
if(rcvRes && ContainsString( rcvRes, "FileReplicationPro Management Console<" )){
	version = "unknown";
	install = "/";
	set_kb_item( name: "FileReplicationPro/Installed", value: TRUE );
	set_kb_item( name: "www/" + port + "/FileReplicationPro", value: version );
	cpe = "cpe:/a:file:replication:pro";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "File Replication Pro", version: version, install: install, cpe: cpe ), port: port );
}
exit( 0 );

