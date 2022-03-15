CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804767" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-09-12 16:51:57 +0530 (Fri, 12 Sep 2014)" );
	script_name( "Joomla! Spider Calendar Component SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Joomla! Spider Calendar Component and is prone to
sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to
execute a sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the /joomla/index.php script not properly sanitizing
user-supplied input to the 'calendar_id' and 'calendar' parameters." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
and script code and SQL statements on the vulnerable system, which may leads to access or modify data in the
underlying database." );
	script_tag( name: "affected", value: "Joomla! Spider version 3.2.6, Prior versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34571" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128189" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?option=com_spidercalendar&calendar_id=1'SQL-Injection-Test";
if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "You have an error in your SQL syntax.*SQL-Injection-Test" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

