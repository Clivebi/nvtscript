CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803385" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-1380", "CVE-2013-1379", "CVE-2013-1378", "CVE-2013-2555" );
	script_bugtraq_id( 58949, 58951, 58947, 58396 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-04-19 11:15:26 +0530 (Fri, 19 Apr 2013)" );
	script_name( "Adobe AIR Multiple Vulnerabilities -02 April 13 (Windows)" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52931" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-11.html" );
	script_xref( name: "URL", value: "http://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause  denial-of-service condition." );
	script_tag( name: "affected", value: "Adobe AIR Version 3.6.0.6090 and prior on Windows" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Error when initializing certain pointer arrays.

  - Integer overflow error." );
	script_tag( name: "solution", value: "Upgrade to version 3.7.0.1530 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe AIR and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "3.6.0.6090" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.7.0.1530", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

