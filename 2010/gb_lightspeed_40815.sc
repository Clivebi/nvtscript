if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100744" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-05 13:46:20 +0200 (Thu, 05 Aug 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-2333" );
	script_bugtraq_id( 40815 );
	script_name( "LiteSpeed Web Server Source Code Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "webmirror.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "LiteSpeed/banner" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40815" );
	script_xref( name: "URL", value: "http://www.litespeedtech.com/latest/litespeed-web-server-4.0.15-released.html" );
	script_xref( name: "URL", value: "http://www.litespeedtech.com" );
	script_tag( name: "summary", value: "LiteSpeed Web Server is prone to a vulnerability that lets attackers
  access source code files." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to retrieve certain files
  from the vulnerable computer in the context of the webserver process.
  Information obtained may aid in further attacks." );
	script_tag( name: "affected", value: "LiteSpeed Web Server versions prior to 4.0.15 are affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "LiteSpeed" )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
phps = http_get_kb_file_extensions( port: port, host: host, ext: "php" );
if( !isnull( phps ) ){
	phps = make_list( phps );
}
else {
	phps = make_list( "/index.php" );
}
for php in phps {
	x++;
	url = php + "\\x00.txt";
	if(buf = http_vuln_check( port: port, url: url, pattern: "<\\?(php)?", check_header: TRUE )){
		if(ContainsString( buf, "Content-Type: text/plain" )){
			if(!http_vuln_check( port: port, url: php, pattern: "<\\?(php)?" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
	if(x >= 3){
		exit( 0 );
	}
}
exit( 99 );

