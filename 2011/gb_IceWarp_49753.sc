if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103279" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-28 12:51:43 +0200 (Wed, 28 Sep 2011)" );
	script_bugtraq_id( 49753 );
	script_cve_id( "CVE-2011-3579", "CVE-2011-3580" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_name( "IceWarp Web Mail Multiple Information Disclosure Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IceWarp/banner" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49753" );
	script_xref( name: "URL", value: "https://www.trustwave.com/spiderlabs/advisories/TWSL2011-013.txt" );
	script_tag( name: "summary", value: "IceWarp Web Mail is prone to multiple information-disclosure
  vulnerabilities." );
	script_tag( name: "impact", value: "Attackers can exploit these issues to gain access to potentially
  sensitive information, and possibly cause denial-of-service conditions. Other attacks may also be possible." );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "IceWarp" )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/webmail", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/server/";
	if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo\\(\\)", usecache: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

