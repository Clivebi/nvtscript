CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810988" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-2495", "CVE-2017-2500", "CVE-2017-2511", "CVE-2017-2496", "CVE-2017-2505", "CVE-2017-2506", "CVE-2017-2514", "CVE-2017-2515", "CVE-2017-2521", "CVE-2017-2525", "CVE-2017-2526", "CVE-2017-2530", "CVE-2017-2531", "CVE-2017-2538", "CVE-2017-2539", "CVE-2017-2544", "CVE-2017-2547", "CVE-2017-6980", "CVE-2017-6984", "CVE-2017-2504", "CVE-2017-2508", "CVE-2017-2510", "CVE-2017-2528", "CVE-2017-2536", "CVE-2017-2549", "CVE-2017-2499" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-16 12:56:34 +0530 (Tue, 16 May 2017)" );
	script_name( "Apple Safari Multiple Vulnerabilities-HT207804" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An inconsistent user interface issue.

  - An issue in Safari's history menu.

  - Multiple memory corruption issues.

  - A logic issue existed in the handling of WebKit Editor commands.

  - A logic issue existed in the handling of WebKit container nodes.

  - A logic issue existed in the handling of pageshow events.

  - A logic issue existed in the handling of WebKit cached frames.

  - A logic issue existed in frame loading." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct cross site scripting and spoofing attacks and can also
  lead to arbitrary code execution and application denial of service." );
	script_tag( name: "affected", value: "Apple Safari versions before 10.1.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Safari 10.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207804" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!safVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: safVer, test_version: "10.1.1" )){
	report = report_fixed_ver( installed_version: safVer, fixed_version: "10.1.1" );
	security_message( data: report );
	exit( 0 );
}

