if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100813" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apache Axis2 Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running Apache Axis2, a Web Services / SOAP / WSDL
  engine, the successor to the widely used Apache Axis SOAP stack." );
	script_xref( name: "URL", value: "http://ws.apache.org/axis2/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8080 );
if( ContainsString( http_get_remote_headers( port: port ), "erver: Simple-Server" ) ){
	dirs = make_list( "/axis2" );
}
else {
	dirs = nasl_make_list_unique( "/axis2", "/imcws", "/WebServiceImpl", "/dswsbobje", "/ws", http_cgi_dirs( port: port ) );
}
for dir in dirs {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/services/Version/getVersion";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	url = dir + "/axis2-admin/";
	req = http_get( item: url, port: port );
	buf2 = http_keepalive_send_recv( port: port, data: req );
	url = dir + "/axis2-web/index.jsp";
	buf3 = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "Service Not found EPR is" )){
		url = dir + "/services/version/getVersion";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
	}
	if(egrep( pattern: "Hello I am Axis2", string: buf, icase: TRUE ) || ( ContainsString( buf, "getVersionResponse" ) && ContainsString( buf, "the Axis2 version is" ) ) || ContainsString( buf, "The system is attempting to access an inactive service: Version" ) || ContainsString( buf, "The service cannot be found for the endpoint reference (EPR)" ) || ContainsString( buf, "Service Not found EPR is" ) || ContainsString( buf2, "<title>Login to Axis2 :: Administration page</title>" ) || ContainsString( buf3, "<title>Axis 2 - Home</title>" )){
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "version is ([0-9.]+)", icase: TRUE );
		if(!isnull( ver[1] )){
			version = chomp( ver[1] );
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/axis2", value: tmp_version );
		set_kb_item( name: "axis2/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:apache:axis2:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:apache:axis2";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Apache Axis2", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

