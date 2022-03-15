CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814320" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-4374", "CVE-2018-4377", "CVE-2018-4372", "CVE-2018-4373", "CVE-2018-4375", "CVE-2018-4376", "CVE-2018-4382", "CVE-2018-4386", "CVE-2018-4392", "CVE-2018-4416", "CVE-2018-4409", "CVE-2018-4378" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 20:25:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-10-31 10:06:26 +0530 (Wed, 31 Oct 2018)" );
	script_name( "Apple Safari Security Updates(HT209196)" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A logic issue due to improper validation.

  - A cross-site scripting issue due to improper URL validation.

  - A resource exhaustion issue due to improper input validation.

  - Multiple memory corruption issues due to poor memory handling and improper
    input validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct universal cross site scripting, arbitrary code execution and
  cause a denial of service condition." );
	script_tag( name: "affected", value: "Apple Safari versions before 12.0.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Safari 12.0.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT209196" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
safVer = infos["version"];
safPath = infos["location"];
if(version_is_less( version: safVer, test_version: "12.0.1" )){
	report = report_fixed_ver( installed_version: safVer, fixed_version: "12.0.1", install_path: safPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

