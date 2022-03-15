if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144087" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-09 03:29:00 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "myLittleAdmin Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of myLittleAdmin

  The script sends a connection request to the server and attempts to detect myLittleAdmin and to extract
  its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8401 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://mylittleadmin.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8401 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "content=\"myLittleAdmin for SQL Server" ) && ContainsString( res, "mla_sql.js" )){
	version = "unknown";
	url = "/history.txt";
	res = http_get_cache( port: port, item: url );
	vers = eregmatch( pattern: "v([0-9.]+) r[0-9]+", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "mylittleadmin/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:mylittletools:mylittleadmin:" );
	if(!cpe){
		cpe = "cpe:/a:mylittletools:mylittleadmin";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "myLittleAdmin", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

