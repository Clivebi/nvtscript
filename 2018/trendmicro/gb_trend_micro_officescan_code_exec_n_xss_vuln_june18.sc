CPE = "cpe:/a:trend_micro:office_scan";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813616" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2017-11393", "CVE-2017-11394" );
	script_bugtraq_id( 100127 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-06 01:29:00 +0000 (Sun, 06 Aug 2017)" );
	script_tag( name: "creation_date", value: "2018-06-27 11:07:13 +0530 (Wed, 27 Jun 2018)" );
	script_name( "Trend Micro OfficeScan RCE And XSS Vulnerabilities (1117762)" );
	script_tag( name: "summary", value: "This host is installed with Trend Micro
  OfficeScan and is prone to multiple code execution and cross site scripting
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper parsing of the tr and T parameters in Proxy.php, the process
    does not properly validate a user-supplied string before using it to execute
    a system call.

  - An input validation error in the third-party component previously used for
    mapping displays." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code on vulnerable installations of Trend Micro OfficeScan." );
	script_tag( name: "affected", value: "Trend Micro OfficeScan versions XG(12.0)
  prior to XG CP 1641 r1 and 11.0 SP1 prior to 11.0 SP1 CP 6392 r1." );
	script_tag( name: "solution", value: "Upgrade to OfficeScan XG CP 1708 or
  11.0 SP1 CP 6392 r1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "30" );
	script_xref( name: "URL", value: "https://success.trendmicro.com/solution/1117762-osce-11-0-sp1-critical-patch-6392-and-osce-xg-critical-patch-1641-is-now-available-in-the-download-c" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_trend_micro_office_scan_detect.sc" );
	script_mandatory_keys( "Trend/Micro/Officescan/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^1[12]\\." )){
	if( version_in_range( version: vers, test_version: "11.0.2995", test_version2: "11.0.6391" ) ){
		fix = "11.0 SP1 CP 6392 r1";
	}
	else {
		if(version_in_range( version: vers, test_version: "12.0", test_version2: "12.0.1707" )){
			fix = "XG CP 1708";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

