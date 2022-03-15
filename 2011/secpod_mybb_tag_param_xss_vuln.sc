CPE = "cpe:/a:mybb:mybb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902804" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_bugtraq_id( 45388 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-27 15:15:15 +0530 (Tue, 27 Dec 2011)" );
	script_name( "MyBB 'tags.php' Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "MyBB/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "MyBB versions 1.6.5 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input
  via the 'tag' parameter in 'tags.php', which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running MyBB and is prone to cross site scripting
  vulnerability." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/45388" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64148" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108156/mybb165-xss.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/96658/mybbtag-xss.txt" );
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
url = dir + "/tags.php?tag=\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document.cookie\\)</script>" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

