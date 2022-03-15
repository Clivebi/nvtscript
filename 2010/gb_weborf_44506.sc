if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100878" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)" );
	script_bugtraq_id( 44506 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Weborf HTTP Request Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44506" );
	script_xref( name: "URL", value: "http://galileo.dmi.unict.it/wiki/weborf/doku.php" );
	script_xref( name: "URL", value: "http://galileo.dmi.unict.it/wiki/weborf/doku.php?id=news:released_0.12.4" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_weborf_webserver_detect.sc", "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Weborf/banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Weborf is prone to a denial-of-service vulnerability.

Remote attackers can exploit this issue to cause the application to
crash, denying service to legitimate users.

Versions prior to Weborf 0.12.4 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Weborf" )){
	exit( 0 );
}
if( safe_checks() ){
	if(!vers = get_kb_item( NASLString( "www/", port, "/Weborf" ) )){
		exit( 0 );
	}
	if(!isnull( vers ) && !ContainsString( "unknown", vers )){
		if(version_is_less( version: vers, test_version: "0.12.4" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
else {
	req = NASLString( "GET\\t/\\tHTTP/1.0\\r\\n\\r\\n" );
	res = http_send_recv( port: port, data: req );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

