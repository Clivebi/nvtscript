CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802705" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_bugtraq_id( 52095 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-03-12 19:22:38 +0530 (Mon, 12 Mar 2012)" );
	script_name( "Joomla com_machine 'Itemid' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://pastebin.com/eDAr20Z1" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/73398" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/109985/joomlamachine-sql.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code" );
	script_tag( name: "affected", value: "Joomla machine component" );
	script_tag( name: "insight", value: "The flaw is due to an input passed via the 'Itemid' parameter to 'index.php'
(when 'option' is set to 'com_machine' & 'view' set to 'machine') is not properly sanitised before being used in a
SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla machine component and is prone to SQL injection
vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
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
url = dir + "/index.php?option=com_machine&view=machine&Itemid='";
if(http_vuln_check( port: port, url: url, pattern: "You have an error in your SQL syntax;", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

