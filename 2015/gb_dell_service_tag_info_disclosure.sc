if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105475" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-12-03 10:52:22 +0100 (Thu, 03 Dec 2015)" );
	script_name( "Dell Foundation Services 'Service Tag' Remote Information Disclosure" );
	script_tag( name: "summary", value: "An issue in Dell Foundation Services, version 2.3.3800.0A00 and below, can be exploited by a malicious website to leak the Dell service tag of a Dell system, which can be used for tracking purposes, or for social engineering." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check the response." );
	script_tag( name: "solution", value: "Update to a Dell Foundation Services > 2.3.3800.0A00 or uninstall Dell Foundation Services" );
	script_tag( name: "insight", value: "Dell Foundation Services starts a HTTPd that listens on port 7779. Generally, requests to the API exposed by this HTTPd must be requests signed using a RSA-1024 key and hashed with SHA512.
One of the JSONP API endpoints to obtain the service tag does not need a valid signature to be provided. Thus, any website can call it." );
	script_tag( name: "affected", value: "Dell Foundation Services 2.3.3800.0A00 and below." );
	script_xref( name: "URL", value: "http://lizardhq.rum.supply/2015/11/25/dell-foundation-services.html" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 7779 );
	script_mandatory_keys( "Microsoft-HTTPAPI/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 7779 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Microsoft-HTTPAPI" ) || !IsMatchRegexp( banner, "^HTTP/1\\.[01] 404" )){
	exit( 0 );
}
url = "/Dell%20Foundation%20Services/eDell/IeDellCapabilitiesApi/REST/ServiceTag";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "application/json" )){
	hb = split( buffer: buf, sep: "\r\n\r\n", keep: FALSE );
	if(isnull( hb[1] )){
		exit( 0 );
	}
	body = str_replace( string: hb[1], find: "\r\n", replace: "" );
	if(IsMatchRegexp( body, "^\"[A-Za-z0-9]+\"$" )){
		rep = http_report_vuln_url( port: port, url: url );
		rep += "\nDell Service Tag: " + body;
		security_message( port: port, data: rep );
		exit( 0 );
	}
}
exit( 0 );

