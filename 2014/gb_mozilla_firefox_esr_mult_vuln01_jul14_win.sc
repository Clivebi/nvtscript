CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804704" );
	script_version( "2020-12-16T12:38:30+0000" );
	script_cve_id( "CVE-2014-1533", "CVE-2014-1538", "CVE-2014-1541" );
	script_bugtraq_id( 67965, 67976, 67979 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-16 12:38:30 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2014-07-01 15:24:18 +0530 (Tue, 01 Jul 2014)" );
	script_name( "Mozilla Firefox ESR Multiple Vulnerabilities-01 July14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A use-after-free error in the 'nsTextEditRules::CreateMozBR()' function

  - A use-after-free error in the 'RefreshDriverTimer::TickDriver()' function
  within the MIL Animation Controller

  - Additional unspecified errors" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 24.x before 24.6 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 24.6 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59170" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-48.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^24\\." ) && version_in_range( version: vers, test_version: "24.0", test_version2: "24.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "24.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

