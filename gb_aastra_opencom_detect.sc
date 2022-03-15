if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103683" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-20 16:20:02 +0100 (Wed, 20 Mar 2013)" );
	script_name( "Aastra OpenCom Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Aastra OpenCom.

  The script sends a connection request to the server and attempts to
  determine the model from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for url in make_list( "/",
	 "/index.html",
	 "/home.asp?state=0" ) {
	buf = http_get_cache( item: url, port: port );
	if(!ContainsString( tolower( buf ), "<title>opencom" )){
		continue;
	}
	typ = eregmatch( pattern: "<TITLE>OpenCom ([^<]+)</TITLE>", string: buf, icase: TRUE );
	if( isnull( typ[1] ) ){
		model = "unknown";
		cpe = "cpe:/h:aastra_telecom:opencom";
	}
	else {
		model = typ[1];
		cpe = "cpe:/h:aastra_telecom:opencom_" + tolower( model );
	}
	register_product( cpe: cpe, location: url, port: port, service: "www" );
	set_kb_item( name: "aastra_opencom/model", value: model );
	log_message( data: build_detection_report( app: "Detected Aastra OpenCom", version: model, install: url, cpe: cpe, concluded: typ[0] ), port: port );
	exit( 0 );
}
exit( 0 );

