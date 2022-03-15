CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817298" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-15960", "CVE-2020-15961", "CVE-2020-15962", "CVE-2020-15963", "CVE-2020-15965", "CVE-2020-15966", "CVE-2020-15964" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-29 17:35:00 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-09-22 12:34:54 +0530 (Tue, 22 Sep 2020)" );
	script_name( "Google Chrome Security Update (stable-channel-update-for-desktop_21-2020-09) - Linux" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - Out of bounds read in storage.

  - Insufficient policy enforcement in extensions.

  - Insufficient policy enforcement in serial.

  - Out of bounds write in V8.

  - Insufficient data validation in media." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 85.0.4183.121." );
	script_tag( name: "solution", value: "Update to Google Chrome version
  85.0.4183.121 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2020/09/stable-channel-update-for-desktop_21.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "85.0.4183.121" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "85.0.4183.121", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

