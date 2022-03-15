if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100309" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-1326" );
	script_bugtraq_id( 28163 );
	script_name( "Gallarific Cross Site Scripting and Authentication Bypass Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/28163" );
	script_xref( name: "URL", value: "http://www.gallarific.com/download.php" );
	script_tag( name: "summary", value: "Gallarific is prone to a cross-site scripting vulnerability and
  multiple authentication-bypass vulnerabilities." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site, steal cookie-based
  authentication credentials, add new categories, add new users, and modify existing users. Other attacks
  are also possible." );
	script_tag( name: "affected", value: "These issues affect both the commercial and the free versions of
  Gallarific." );
	script_tag( name: "solution", value: "Updates are available. Please contact the vendor for details." );
	script_tag( name: "qod", value: "50" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/photos", "/gallery", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/search.php?dosearch=true&query=\"><script>alert(document.cookie)</script>";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(isnull( buf )){
		continue;
	}
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>alert\\(document\\.cookie\\)</script>", string: buf, icase: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

