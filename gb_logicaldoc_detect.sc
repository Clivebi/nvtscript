if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140769" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-13 10:43:53 +0700 (Tue, 13 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "LogicalDOC Detection" );
	script_tag( name: "summary", value: "Detection of LogicalDOC.

The script sends a connection request to the server and attempts to detect LogicalDOC." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.logicaldoc.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", "/logicaldoc", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	names = make_list( "frontend",
		 "login" );
	for name in names {
		res = http_get_cache( port: port, item: dir + "/" + name + "/" + name + ".nocache.js" );
		ub = eregmatch( pattern: ",Ub='([^']+)", string: res );
		if( isnull( ub[1] ) ) {
			continue;
		}
		else {
			found_name = name;
			break;
		}
	}
	if(isnull( ub[1] )){
		continue;
	}
	url = dir + "/" + found_name + "/" + ub[1] + ".cache.html";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "logicaldoc" )){
		version = "unknown";
		set_kb_item( name: "logicalDOC/installed", value: TRUE );
		cpe = "cpe:/a:logicaldoc:logicaldoc";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "LogicalDOC", version: version, install: install, cpe: cpe ), port: port );
		exit( 0 );
	}
}
exit( 0 );

