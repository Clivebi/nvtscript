CPE = "cpe:/a:phpnuke:php-nuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902612" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP-Nuke 'sid' Parameter SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_nuke_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "php-nuke/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to add, modify or
  delete data in the back end database." );
	script_tag( name: "affected", value: "PHP-Nuke versions 5.6, 6.0, 6.5 RC1, 6.5 RC2, 6.5 RC3, 6.5" );
	script_tag( name: "insight", value: "The flaw is caused by input validation errors in the 'article.php'
  when processing user-supplied data in 'sid' parameter, which could be exploited
  by attackers to execute SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running PHP-Nuke and is prone to SQL injection
  vulnerability." );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/16550" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/11599" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0147.html" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/article.php?sid=sid=24%27";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "mysql_fetch_row()" ) && ContainsString( res, "MySQL result" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

