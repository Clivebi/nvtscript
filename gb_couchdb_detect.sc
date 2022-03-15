if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100571" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "CouchDB Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "CouchDB/banner" );
	script_require_ports( "Services/www", 5984 );
	script_tag( name: "summary", value: "This host is running CouchDB. Apache CouchDB is a document-oriented
  database that can be queried and indexed in a MapReduce fashion using
  JavaScript. CouchDB also offers incremental replication with
  bi-directional conflict detection and resolution." );
	script_xref( name: "URL", value: "http://couchdb.apache.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 5984 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: CouchDB/" )){
	exit( 0 );
}
set_kb_item( name: "couchdb/installed", value: TRUE );
vers = "unknown";
version = eregmatch( pattern: "Server: CouchDB/([^ ]+)", string: banner );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "couchdb/version", value: vers );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:apache:couchdb:" );
	if(!cpe){
		cpe = "cpe:/a:apache:couchdb";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache CouchDB", version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

