CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802125" );
	script_version( "$Revision: 11552 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)" );
	script_bugtraq_id( 48685 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Joomla com_foto SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103077/joomlafoto-sql.txt" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "Joomla foto component." );
	script_tag( name: "insight", value: "The flaw is due to input passed via the 'id_categoria' parameter to
'index.php' (when 'option' is set to 'com_foto' & 'task' set to 'categoria') is not properly sanitised before
being used in a SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla foto component and is prone to SQL injection
vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
sndReq = http_get( item: dir + "/index.php?option=com_foto&amp;task=categoria&amp;id_categoria='", port: port );
rcvRes = http_send_recv( port: port, data: sndReq );
if(ContainsString( rcvRes, ">Warning<" ) && ContainsString( rcvRes, "Invalid argument supplied" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

