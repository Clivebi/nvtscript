CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814070" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-18499", "CVE-2018-12379", "CVE-2018-12385", "CVE-2018-12383", "CVE-2018-12376" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 15:50:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "creation_date", value: "2018-10-05 11:07:48 +0530 (Fri, 05 Oct 2018)" );
	script_name( "Mozilla Thunderbird Security Updates (mfsa_2018-20_2018-25) - Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An use-after-free error in refresh driver timers.

  - An use-after-free error in IndexedDB.

  - A same-origin policy violation using meta refresh and performance.getEntries to steal cross-origin URLs.

  - An out-of-bounds write error with malicious MAR file.

  - An error related to cached data in the user profile directory.

  - An error related to setting of a master password.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose sensitive information, cause denial of service and run arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 60.2.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 60.2.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-25" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "60.2.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "60.2.1", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

