if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802445" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2012-4680" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-08-20 16:21:46 +0530 (Mon, 20 Aug 2012)" );
	script_name( "IOServer Trailing Backslash Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.foofus.net/?page_id=616" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Aug/223" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 81 );
	script_mandatory_keys( "IOServer/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks." );
	script_tag( name: "affected", value: "IOServer version 1.0.18.0 and prior" );
	script_tag( name: "insight", value: "The flaws are due to improper validation of URI containing
  ../ (dot dot) sequences, which allows attackers to read arbitrary files
   via directory traversal attacks." );
	script_tag( name: "solution", value: "Upgrade to IOServer version 1.0.19.0 or later." );
	script_tag( name: "summary", value: "This host is running IOServer and is prone to multiple directory
  traversal vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.ioserver.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 81 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: IOServer" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	url = "/.../.../.../.../" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

