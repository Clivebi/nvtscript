CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818036" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-21206", "CVE-2021-21220" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 14:27:00 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-23 10:52:28 +0530 (Tue, 23 Feb 2021)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2021-04)-Linux" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - Use after free in Blink.

  - Insufficient validation of untrusted input in V8 for x86_64." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code and gain access to sensitive data." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 89.0.4389.128 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  89.0.4389.128 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2021/04/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "89.0.4389.128" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "89.0.4389.128", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

