if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103420" );
	script_bugtraq_id( 51994 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Sonexis ConferenceManager Multiple Information Disclosure and Security Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51994" );
	script_xref( name: "URL", value: "http://pentest.snosoft.com/2012/02/13/netragard-uncovers-0-days-in-sonexis-conferencemanager/" );
	script_xref( name: "URL", value: "http://www.sonexis.com/products/index.asp" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-15 10:59:59 +0100 (Wed, 15 Feb 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Reportedly, the issue is fixed, however, Symantec has not confirmed
this. Please contact the vendor for more information." );
	script_tag( name: "summary", value: "Sonexis ConferenceManager is prone to remote information-disclosure
and security-bypass vulnerabilities." );
	script_tag( name: "impact", value: "An attacker may exploit these issues to obtain sensitive information
and bypass certain security restrictions." );
	script_tag( name: "affected", value: "Sonexis ConferenceManager versions 10.0.40 and prior are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/Login/HostLogIn.asp?ie=0";
	if(http_vuln_check( port: port, url: url, pattern: "Sonexis ConferenceManager</title>" )){
		url = dir + "/admin/backup/settings.asp";
		if(http_vuln_check( port: port, url: url, pattern: "External Location for Download", extra_check: make_list( "User ID:",
			 "Password:",
			 "<Title>Upload" ) )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

