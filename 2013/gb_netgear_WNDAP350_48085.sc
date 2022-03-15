if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103702" );
	script_bugtraq_id( 48085 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "NetGear WNDAP350 Wireless Access Point Multiple Information Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48085" );
	script_xref( name: "URL", value: "http://www.netgear.com/" );
	script_xref( name: "URL", value: "https://revspace.nl/RevelationSpace/NewsItem11x05x30x0" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-04-22 13:20:27 +0200 (Mon, 22 Apr 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "NetGear WNDAP350 wireless access point is prone to multiple remote information-
disclosure issues because it fails to restrict access to sensitive
information.

A remote attacker can exploit these issues to obtain sensitive
information that can aid in launching further attacks.

WNDAP350 with firmware 2.0.1 and 2.0.9 are vulnerable. Other firmware
versions may also be affected." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_vuln_check( port: port, url: "/index.php?page=master", pattern: "<title>Netgear" )){
	url = "/downloadFile.php";
	if(http_vuln_check( port: port, url: url, pattern: "system:basicSettings:adminPasswd" )){
		security_message( port: port );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

