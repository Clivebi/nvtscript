CPE = "cpe:/a:sixapart:movable_type";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16169" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Movable Type initialization script found" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Rich Walchuck" );
	script_family( "Web application abuses" );
	script_dependencies( "mt_detect.sc" );
	script_mandatory_keys( "movabletype/detected" );
	script_tag( name: "solution", value: "Remove the mt-load.cgi script after installation." );
	script_tag( name: "summary", value: "mt-load.cgi is installed by the Movable Type Publishing Platform." );
	script_tag( name: "impact", value: "Failure to remove mt-load.cgi could enable someone else to create
 a weblog in your Movable Type installation, and possibly gain access to your data." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/mt/mt-load.cgi";
if(http_is_cgi_installed_ka( item: url, port: port )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

