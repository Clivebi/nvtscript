CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814664" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2018-18500", "CVE-2018-18503", "CVE-2018-18504", "CVE-2018-18505", "CVE-2018-18506", "CVE-2018-18502", "CVE-2018-18501" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-07 15:42:00 +0000 (Thu, 07 Feb 2019)" );
	script_tag( name: "creation_date", value: "2019-01-30 13:05:57 +0530 (Wed, 30 Jan 2019)" );
	script_name( "Mozilla Firefox Security Updates(mfsa_2018-31_2019-03)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Memory safety bugs.

  - Proxy Auto-Configuration file can define localhost access to be proxied.

  - Lack of message validation in the listener process for an Inter-process Communication.

  - Multiple memory corruption errors.

  - An use after free error." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to cause denial of service condition, escalate privileges and run arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 65.0 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 65.0 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-01/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "65.0" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "65.0", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

