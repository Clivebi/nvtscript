if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802311" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-07-19 14:57:20 +0200 (Tue, 19 Jul 2011)" );
	script_cve_id( "CVE-2011-2743" );
	script_bugtraq_id( 48672 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Chyrp Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103098/oCERT-2011-001-JAHx113.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to hijack the session of the
  administrator or to read arbitrary accessible files or to gain sensitive
  information by executing arbitrary scripts." );
	script_tag( name: "affected", value: "Chyrp version prior to 2.1.1." );
	script_tag( name: "insight", value: "Multiple flaws are due to.

  - Insufficient input sanitisation on the parameters passed to pages related
    to administration settings, the javascript handler and the index handler
    leads to arbitrary javascript injection in the context of the user session.

  - Insufficient path sanitisation on the root 'action' query string parameter

  - 'title' and 'body' parameters are not initialised in the 'admin/help.php'
    file resulting in cross site scripting." );
	script_tag( name: "solution", value: "Upgrade to Chyrp version 2.1.1 or later." );
	script_tag( name: "summary", value: "The host is running Chyrp and is prone to multiple vulnerabilities." );
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
for dir in nasl_make_list_unique( "/blog", "/chyrp", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( res, "Powered by" ) && ContainsString( res, ">Chyrp<" )){
		xss = "/admin/help.php?title=\"><script>alert(document.cookie);</script>";
		req = http_get( item: dir + xss, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"><script>alert(document.cookie);</script>\"" )){
			report = http_report_vuln_url( port: port, url: xss );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

