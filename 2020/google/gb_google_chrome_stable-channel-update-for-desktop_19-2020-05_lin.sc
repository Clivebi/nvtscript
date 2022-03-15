CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817026" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468", "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6477", "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6485", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6491" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-08 03:15:00 +0000 (Wed, 08 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-05-22 09:22:08 +0530 (Fri, 22 May 2020)" );
	script_name( "Google Chrome Security Update (stable-channel-update-for-desktop_19-2020-05) - Linux" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - Use after free in reader mode.

  - Use after free in media.

  - Use after free in WebRTC.

  - Type Confusion in V8.

  - Insufficient policy enforcement in developer tools.

  - Insufficient validation of untrusted input in clipboard.

  - Insufficient policy enforcement in Blink.

  - Use after free in Blink.

  - Incorrect security UI in full screen.

  - Insufficient policy enforcement in tab strip.

  - Inappropriate implementation in installer.

  - Inappropriate implementation in full screen.

  - Inappropriate implementation in sharing.

  - Insufficient policy enforcement in enterprise.

  - Insufficient policy enforcement in URL formatting.

  - Insufficient policy enforcement in payments.

  - Insufficient data validation in ChromeDriver.

  - Insufficient data validation in media router.

  - Insufficient policy enforcement in navigations.

  - Insufficient policy enforcement in downloads.

  - Inappropriate implementation in developer tools.

  - Insufficient data validation in loader.

  - Incorrect security UI in site information." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code, read sensitive information, bypass security restrictions,
  perform unauthorized actions or cause denial of service conditions." );
	script_tag( name: "affected", value: "Google Chrome version prior to 83.0.4103.61." );
	script_tag( name: "solution", value: "Update to Google Chrome 83.0.4103.61 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2020/05/stable-channel-update-for-desktop_19.html" );
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
if(version_is_less( version: vers, test_version: "83.0.4103.61" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "83.0.4103.61", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

