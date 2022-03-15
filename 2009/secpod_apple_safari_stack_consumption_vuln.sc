CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900870" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3272" );
	script_name( "Apple Safari 'WebKit.dll' Stack Consumption Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9606" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/385690.php" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause stack consumption
  which may lead to the application crash." );
	script_tag( name: "affected", value: "Apple Safari version prior to 4.0." );
	script_tag( name: "insight", value: "The flaw is due to error in 'WebKit.dll' in WebKit which can be caused via
  JavaScript code that calls eval on a long string composed of 'A/' sequences." );
	script_tag( name: "solution", value: "Upgrade to Safari version 4.0 or later." );
	script_tag( name: "summary", value: "This host has Apple Safari installed and is prone to Stack
  Consumption vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.30.17.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 4.0 (4.30.17.0)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

