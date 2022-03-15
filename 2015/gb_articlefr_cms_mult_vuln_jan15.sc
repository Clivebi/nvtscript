if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805262" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-1364", "CVE-2015-1363" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-29 16:47:29 +0530 (Thu, 29 Jan 2015)" );
	script_name( "ArticleFR CMS Multiple Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "The host is installed with ArticleFR CMS
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'username' parameter
  to register and 'q' parameter to search/v/ is not properly sanitised before
  being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database and execute
  arbitrary HTML and script code in a users browser session in the context of an
  affected site." );
	script_tag( name: "affected", value: "ArticleFR CMS version 3.0.5, Prior
  versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to 3.0.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35857" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/130066" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jan/81" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jan/101" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://articlefr.cf" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/articleFR", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(rcvRes && IsMatchRegexp( rcvRes, "Powered by.*>ArticleFR" )){
		url = dir + "/search/v/?q=<script>alert(document.cookie)</script>";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "Powered by.*>ArticleFR" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

