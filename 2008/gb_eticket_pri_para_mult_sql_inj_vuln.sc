if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800141" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5165" );
	script_bugtraq_id( 29973 );
	script_name( "eTicket pri Parameter Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/30877" );
	script_xref( name: "URL", value: "http://www.eticketsupport.com/announcements/170_is_in_the_building-t91.0.html" );
	script_xref( name: "URL", value: "http://www.digitrustgroup.com/advisories/web-application-security-eticket2.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful attack could allow manipulation of the database by injecting
  arbitrary SQL queries." );
	script_tag( name: "affected", value: "eTicket Version 1.5.7 and prior." );
	script_tag( name: "insight", value: "Input passed to the pri parameter of index.php, open.php, open_raw.php, and
  newticket.php is not properly sanitised before being used in SQL queries." );
	script_tag( name: "solution", value: "Update to Version 1.7.0 or later." );
	script_tag( name: "summary", value: "The host is running eTicket, which is prone to multiple SQL Injection
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/eTicket", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/license.txt", port: port );
	if(rcvRes && IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "eTicket" )){
		eTicVer = eregmatch( pattern: "eTicket ([0-9.]+)", string: rcvRes );
		if(eTicVer[1] != NULL){
			if(version_is_less_equal( version: eTicVer[1], test_version: "1.5.7" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

