CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902397" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)" );
	script_bugtraq_id( 48658 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Joomla com_xmap SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103010/joomlaxmap1211-sql.txt" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code" );
	script_tag( name: "affected", value: "Joomla Xmap component version 1.2.11" );
	script_tag( name: "insight", value: "The flaw is due to input passed via 'view' parameter to 'index.php' is not
  properly sanitised before being used in a SQL query." );
	script_tag( name: "solution", value: "Upgrade to Joomla Xmap component version 1.2.12 or later." );
	script_tag( name: "summary", value: "This host is running Joomla xmap component and is prone to SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?option=com_xmap&tmpl=component&Itemid=999&view='";
sndReq = http_get( item: url, port: port );
rcvRes = http_send_recv( port: port, data: sndReq );
if(ContainsString( rcvRes, ">Warning<" ) && ContainsString( rcvRes, "Invalid argument supplied" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

