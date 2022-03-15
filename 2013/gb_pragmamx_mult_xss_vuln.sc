if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803345" );
	script_version( "2021-07-02T02:00:36+0000" );
	script_bugtraq_id( 53669 );
	script_cve_id( "CVE-2012-2452" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-02 02:00:36 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-12 15:46:00 +0000 (Wed, 12 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-03-25 16:37:00 +0530 (Mon, 25 Mar 2013)" );
	script_name( "PragmaMX Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2012/May/126" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23090" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/113035" );
	script_xref( name: "URL", value: "http://www.pragmamx.org/Content-pragmaMx-changelog-item-75.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
  or web script in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "PragmaMX version 1.12.1 and prior." );
	script_tag( name: "insight", value: "Multiple flaws due to improperly sanitized 'name' parameter in modules.php and
  'img_url' parameter in img_popup.php before they are being returned to the user." );
	script_tag( name: "solution", value: "Upgrade to PragmaMx 1.12.2 or later." );
	script_tag( name: "summary", value: "The host is installed with PragmaMX and is prone to multiple cross
  site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/pragmamx", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, ">pragmaMx" )){
		url = dir + "/includes/wysiwyg/spaw/editor/plugins/imgpopup/img_popup.php?" + "img_url=\"><script>alert(document.cookie)</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

