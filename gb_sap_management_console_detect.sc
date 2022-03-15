if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103829" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-11-13 12:08:59 +0100 (Wed, 13 Nov 2013)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SAP Management Console Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract
  the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 50013 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 50013 );
url = "/sapmc/sapmc.html";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "SAP Management Console" ) && ContainsString( buf, "com.sap.managementconsole.applet" )){
	soap = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\r\n" + "<SOAP-ENV:Header>\r\n" + "<sapsess:Session xlmns:sapsess=\"http://www.sap.com/webas/630/soap/features/session/\">\r\n" + "<enableSession>true</enableSession>\r\n" + "</sapsess:Session>\r\n" + "</SOAP-ENV:Header>\r\n" + "<SOAP-ENV:Body>\r\n" + "<ns1:GetVersionInfo xmlns:ns1=\"urn:SAPControl\"></ns1:GetVersionInfo>\r\n" + "</SOAP-ENV:Body>\r\n" + "</SOAP-ENV:Envelope>\r\n\r\n";
	req = http_post_put_req( port: port, url: "/", data: soap, add_headers: make_array( "SOAPAction", "", "Content-Type", "text/xml; charset=UTF-8" ) );
	result = http_send_recv( port: port, data: req, bodyonly: FALSE );
	vers = eregmatch( pattern: "<VersionInfo>([^<]+)</VersionInfo>", string: result );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "www/" + port + "/sap_management_console/version", value: version );
	}
	set_kb_item( name: "sap_management_console/installed", value: TRUE );
	set_kb_item( name: "sap_management_console/port", value: port );
	cpe = "cpe:/a:sap:netweaver";
	register_product( cpe: cpe, location: port + "/tcp", port: port );
	log_message( data: build_detection_report( app: "SAP Management Console", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

