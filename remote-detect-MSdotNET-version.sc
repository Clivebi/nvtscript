if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101007" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-15 21:21:09 +0100 (Sun, 15 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Microsoft dotNET version grabber" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "It's recommended to disable verbose error displaying to avoid version detection.
  this can be done through the IIS management console." );
	script_tag( name: "summary", value: "The remote host seems to have Microsoft .NET installed." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Microsoft dotNET version grabber";
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
page = NASLString( "/" + rand() + ".aspx" );
request = http_get( item: page, port: port );
response = http_keepalive_send_recv( port: port, data: request, bodyonly: FALSE );
dotNet_header = eregmatch( pattern: "Microsoft .NET Framework Version:([0-9.]+)", string: response, icase: TRUE );
aspNet_header = eregmatch( pattern: "ASP.NET Version:([0-9.]+)", string: response, icase: TRUE );
if(( ContainsString( response, "Version Information" ) ) && dotNet_header){
	report = "Detected " + dotNet_header[0];
	set_kb_item( name: "dotNET/install", value: TRUE );
	set_kb_item( name: "dotNET/port", value: port );
	set_kb_item( name: "dotNET/version", value: dotNet_header[1] );
	cpe = build_cpe( value: dotNet_header[1], exp: "^([0-9.]+)", base: "cpe:/a:microsoft:.net_framework:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
	if(ContainsString( response, aspNet_header )){
		report += " and " + aspNet_header[0];
		set_kb_item( name: "aspNET/installed", value: TRUE );
		set_kb_item( name: "aspNET/version", value: aspNet_header[1] );
	}
	log_message( port: port, data: report );
}
exit( 0 );

