CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11218" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Tomcat /status information disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 StrongHoldNet" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tomcat/http/detected" );
	script_tag( name: "solution", value: "If you don't use this feature, comment the appropriate section in
  your httpd.conf file. If you really need it, limit its access to
  the administrator's machine." );
	script_tag( name: "summary", value: "Requesting the URI /status gives information about
  the currently running Tomcat." );
	script_tag( name: "impact", value: "It also allows anybody to reset (ie: permanently delete) the current
  statistics. Additional information gathering about the target is possible as well." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/status";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, "Status information for" ) ) && ( ContainsString( res, "<a href='jkstatus?scoreboard.reset'>reset</a>" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

