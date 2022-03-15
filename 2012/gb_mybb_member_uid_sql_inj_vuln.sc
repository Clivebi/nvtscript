CPE = "cpe:/a:mybb:mybb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802636" );
	script_version( "$Revision: 11374 $" );
	script_bugtraq_id( 53814 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-06-08 12:12:12 +0530 (Fri, 08 Jun 2012)" );
	script_name( "MyBB 'member.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53814" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/76097" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/113300/mybb168-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "MyBB/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to compromise
  the application, access or modify data or exploit vulnerabilities in the
  underlying database." );
	script_tag( name: "affected", value: "MyBB version 1.6.8" );
	script_tag( name: "insight", value: "The application fails to sufficiently sanitize user supplied input
  to the 'uid' parameter in 'member.php' before using it in an SQL query, which
  allows attackers to execute arbitrary SQL commands in the context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running MyBB and is prone to SQL injection
  vulnerability." );
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
url = dir + "/member.php?action=profile&uid='";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "You have an error in your SQL syntax", extra_check: "MyBB has experienced an internal SQL error" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );
