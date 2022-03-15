CPE = "cpe:/a:dotnetnuke:dotnetnuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802306" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "DotNetNuke Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotnetnuke_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dotnetnuke/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain unauthorized
  access to the server." );
	script_tag( name: "affected", value: "DotNetNuke version prior to 5.x." );
	script_tag( name: "insight", value: "Multiple flaws are present in DotNetNuke. The application fails
  to revalidate file and folder permissions correctly for uploads. This allows
  remote file upload and unauthorized access to the server, files and database." );
	script_tag( name: "solution", value: "Upgrade to DotNetNuke version 6.2.5 or later." );
	script_tag( name: "summary", value: "The host is running DotNetNuke and is prone to multiple
  vulnerabilities." );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/16462" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.dotnetnuke.com/" );
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
for path in make_list( "FeedbackDesigner",
	 "FlashSlide",
	 "TellMyFriends",
	 "Complete%20Feedback%20Designer",
	 "FlashBoard" ) {
	url = dir + "/DesktopModules/" + path + "/ajaxfbs/browser.html";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "create the folder" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

