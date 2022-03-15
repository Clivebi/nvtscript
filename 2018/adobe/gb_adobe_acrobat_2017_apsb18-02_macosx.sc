CPE = "cpe:/a:adobe:acrobat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812936" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-4872", "CVE-2018-4890", "CVE-2018-4904", "CVE-2018-4910", "CVE-2018-4917", "CVE-2018-4888", "CVE-2018-4892", "CVE-2018-4902", "CVE-2018-4911", "CVE-2018-4913", "CVE-2018-4879", "CVE-2018-4895", "CVE-2018-4898", "CVE-2018-4901", "CVE-2018-4915", "CVE-2018-4916", "CVE-2018-4918", "CVE-2018-4880", "CVE-2018-4881", "CVE-2018-4882", "CVE-2018-4883", "CVE-2018-4884", "CVE-2018-4885", "CVE-2018-4886", "CVE-2018-4887", "CVE-2018-4889", "CVE-2018-4891", "CVE-2018-4893", "CVE-2018-4894", "CVE-2018-4896", "CVE-2018-4897", "CVE-2018-4899", "CVE-2018-4900", "CVE-2018-4903", "CVE-2018-4905", "CVE-2018-4906", "CVE-2018-4907", "CVE-2018-4908", "CVE-2018-4909", "CVE-2018-4912", "CVE-2018-4914", "CVE-2018-4997", "CVE-2018-4998", "CVE-2018-4999" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-15 16:54:40 +0530 (Thu, 15 Feb 2018)" );
	script_name( "Adobe Acrobat 2017 Multiple Vulnerabilities-apsb18-02 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat 2017
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple Out-of-bounds read errors.

  - Multiple Out-of-bounds write errors.

  - Multiple Use-after-free errors.

  - Multiple Heap Overflow errors.

  - A memory corruption error.

  - A Security Mitigation Bypass error." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to gain escalated privileges, execute arbitrary code on affected
  system and take control of the affected system." );
	script_tag( name: "affected", value: "Adobe Acrobat 2017.011.30070 and earlier
  versions on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat 2017 version
  2017.011.30078 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb18-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Acrobat/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "17.0", test_version2: "17.011.30077" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "17.011.30078 (2017.011.30078)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

