if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801911" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_cve_id( "CVE-2011-1668" );
	script_bugtraq_id( 47126 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "AR Web Content Manager (AWCM) 'search.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=179" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/47126/" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SECPOD_AWCM_XSS.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary HTML
  code in a user's browser session in the context of a vulnerable application." );
	script_tag( name: "affected", value: "AWCM CMS version 2.2 and prior" );
	script_tag( name: "insight", value: "Input passed via the 'search' parameter in 'search' action in search.php is not
  properly verified before it is returned to the user. This can be exploited
  to execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site. This may allow an attacker to steal cookie-based
  authentication credentials and launch further attacks." );
	script_tag( name: "solution", value: "Apply the patch from below link." );
	script_tag( name: "summary", value: "The host is running AR Web Content Manager (AWCM) and is prone to Cross-Site
  Scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.zshare.net/download/8818096688e1e96a/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
awcmPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/awcm", "/AWCM", "/", http_cgi_dirs( port: awcmPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: awcmPort );
	if(ContainsString( rcvRes, ">AWCM" )){
		if(http_vuln_check( port: awcmPort, url: dir + "/search.php?search=<script>" + "alert(\"XSS-Test\")</script>&where=all", pattern: "(<script>alert.\"XSS-Test\".</script>)", check_header: TRUE )){
			security_message( port: awcmPort );
			exit( 0 );
		}
	}
}
exit( 99 );

