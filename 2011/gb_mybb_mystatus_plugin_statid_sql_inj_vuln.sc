CPE = "cpe:/a:mybb:mybb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802040" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "MyBB MyStatus Plugin process-mystatus.php 'statid' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46360" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17972" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/105744" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "MyBB/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code and gain sensitive information." );
	script_tag( name: "affected", value: "MyBB MyStatus Plugin Version 3.1, Other versions may also
  be affected." );
	script_tag( name: "insight", value: "The flaw is due to input passed via 'statid' parameter to
  'process-mystatus.php', which is not properly sanitised before being
  used in a SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running MyBB with MyStatus Plugin and is prone to
  SQL injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/process-mystatus.php?action=delete&statid='SQLi";
if(http_vuln_check( port: port, url: url, pattern: "MyBB has experienced an " + "internal SQL error and cannot continue.", extra_check: "You have an" + " error in your SQL syntax" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

