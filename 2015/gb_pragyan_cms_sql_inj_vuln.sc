if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805159" );
	script_version( "2021-03-11T10:58:32+0000" );
	script_cve_id( "CVE-2015-1471" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2015-04-03 11:17:18 +0530 (Fri, 03 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Pragyan CMS SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "Pragyan CMS is prone to an SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the
  response." );
	script_tag( name: "insight", value: "Flaw is due to the userprofile.lib.php
  script not properly sanitizing user-supplied input appended to 'user:#'
  in the URL." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Pragyan CMS version 3.0. Prior versions
  may also be affected." );
	script_tag( name: "solution", value: "As a workaround locate the file
  userprofile.lib.php and use the patch provided in the referenced link." );
	script_xref( name: "URL", value: "http://pastebin.com/ip2gGYuS" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2015/q1/402" );
	script_xref( name: "URL", value: "https://github.com/delta/pragyan/issues/206" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Feb/18" );
	script_xref( name: "URL", value: "http://sroesemann.blogspot.de/2015/01/sroeadv-2015-11.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
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
for dir in nasl_make_list_unique( "/", "/pragyan", "/cms", "/pragyancms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/home/+login", port: port );
	if(ContainsString( res, ">Pragyan CMS" ) && ContainsString( res, "Login<" )){
		url = dir + "/user:1'SQL-INJECTION-TEST";
		if(http_vuln_check( port: port, url: url, check_header: FALSE, pattern: "You have an error in your SQL syntax", extra_check: "SQL-INJECTION-TEST" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

