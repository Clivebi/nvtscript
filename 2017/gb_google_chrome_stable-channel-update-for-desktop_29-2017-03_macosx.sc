CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810598" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_cve_id( "CVE-2017-5055", "CVE-2017-5054", "CVE-2017-5052", "CVE-2017-5056", "CVE-2017-5053" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-03-30 14:39:12 +0530 (Thu, 30 Mar 2017)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_29-2017-03)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use after free error in printing.

  - Heap buffer overflow error in V8.

  - Bad cast in Blink.

  - Use after free error in Blink.

  - Out of bounds memory access error in V8." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to corrupt memory and cause denial
  of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 57.0.2987.133 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome 57.0.2987.133 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2017/03/stable-channel-update-for-desktop_29.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "57.0.2987.133" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "57.0.2987.133" );
	security_message( data: report );
	exit( 0 );
}

