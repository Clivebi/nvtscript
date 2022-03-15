CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815268" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_cve_id( "CVE-2019-5850", "CVE-2019-5860", "CVE-2019-5853", "CVE-2019-5851", "CVE-2019-5859", "CVE-2019-5856", "CVE-2019-5855", "CVE-2019-5865", "CVE-2019-5858", "CVE-2019-5864", "CVE-2019-5862", "CVE-2019-5861", "CVE-2019-5857", "CVE-2019-5854", "CVE-2019-5852" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-26 14:02:00 +0000 (Tue, 26 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-07-31 10:43:25 +0530 (Wed, 31 Jul 2019)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_30-2019-07)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A use-after-free issue in offline page fetcher and PDFium.

  - A memory corruption issue in regexp length check.

  - A use-after-poison issue in offline audio context.

  - URIs can load alternative browsers.

  - Insufficient checks on filesystem.

  - An integer overflow issue in PDFium and PDFium text rendering.

  - A compromised render can bypass site isolation.

  - Insufficient filtering of Open URL service parameters.

  - Insufficient port filtering in CORS for extensions.

  - AppCache not robust to compromised renderers.

  - Incorrect checking of click location.

  - Comparison of -0 and null yields crash.

  - Object leak of utility functions." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary code in the context of the browser, obtain
  sensitive information, bypass security restrictions, perform unauthorized
  actions, or cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Google Chrome version prior to 76.0.3809.87 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  76.0.3809.87 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2019/07/stable-channel-update-for-desktop_30.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "76.0.3809.87" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "76.0.3809.87", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

