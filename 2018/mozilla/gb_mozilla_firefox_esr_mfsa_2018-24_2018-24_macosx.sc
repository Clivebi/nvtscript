CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814064" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-12386", "CVE-2018-12387" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 18:38:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "creation_date", value: "2018-10-03 17:02:05 +0530 (Wed, 03 Oct 2018)" );
	script_name( "Mozilla Firefox ESR Security Updates(mfsa_2018-24_2018-24)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  ESR and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A type confusion error in JavaScript.

  - The JavaScript JIT compiler improperly inlines Array.prototype.push with
    multiple arguments." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct code execution and disclose sensitive information." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 60.2.2 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 60.2.2
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-24" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "60.2.2" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "60.2.2", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

