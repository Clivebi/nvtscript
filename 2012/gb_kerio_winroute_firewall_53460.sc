if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103487" );
	script_bugtraq_id( 53460 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Kerio WinRoute Firewall Web Server Remote Source Code Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53460" );
	script_xref( name: "URL", value: "http://www.kerio.com" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-05-11 13:52:12 +0200 (Fri, 11 May 2012)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Kerio_WinRoute/banner" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "Kerio WinRoute Firewall is prone to a remote source-code-
disclosure vulnerability because it fails to properly sanitize user-
supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view the source code
of files in the context of the server process, this may aid in
further attacks." );
	script_tag( name: "affected", value: "Versions prior to Kerio WinRoute Firewall 6.0.0 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Kerio WinRoute Firewall" )){
	exit( 0 );
}
url = "/nonauth/login.php%00.txt";
if(http_vuln_check( port: port, url: url, pattern: "require_once", extra_check: make_list( "configNonauth",
	 "CORE_PATH" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

