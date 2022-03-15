CPE = "cpe:/a:benjamin_curtis:phpbugtracker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15751" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 10153 );
	script_name( "phpBugTracker bug.php SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "phpBugTracker_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpBugTracker/installed" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software" );
	script_tag( name: "summary", value: "The remote host is using phpBugTracker, a PHP based bug tracking engine.

 There is a bug in the remote version of this software which makes it
 vulnerable to an SQL injection vulnerability. An attacker may exploit
 this flaw to execute arbitrary SQL statements against the remote database." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
url = dir + "/bug.php?op=vote&bugid=1'";
sendReq = http_get( item: url, port: port );
recvRes = http_keepalive_send_recv( port: port, data: sendReq, bodyonly: TRUE );
if(ContainsString( recvRes, "DB Error: syntax error" ) || ContainsString( recvRes, "MySQL server version for" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

