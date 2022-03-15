CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813328" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-6118" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-28 17:45:00 +0000 (Fri, 28 Jun 2019)" );
	script_tag( name: "creation_date", value: "2018-05-03 12:41:09 +0530 (Thu, 03 May 2018)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_26-2018-04)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An use after free error in Media Cache.

  - Various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation can potentially
  result in the execution of arbitrary code or even enable full remote code
  execution capabilities and some unspecified impacts." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 66.0.3359.139 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  66.0.3359.139 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/04/stable-channel-update-for-desktop_26.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
chr_ver = infos["version"];
chr_path = infos["location"];
if(version_is_less( version: chr_ver, test_version: "66.0.3359.139" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "66.0.3359.139", install_path: chr_path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

