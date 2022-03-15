CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816739" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-6454", "CVE-2020-6423", "CVE-2020-6455", "CVE-2020-6430", "CVE-2020-6456", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-02 12:15:00 +0000 (Thu, 02 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-08 13:01:58 +0530 (Wed, 08 Apr 2020)" );
	script_name( "Google Chrome Security Update (stable-channel-update-for-desktop_7-2020-04) - Mac OS X" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - A use after free issue in extensions.

  - A use after free issue in audio.

  - An out of bounds read issue in WebSQL.

  - A type confusion issue in V8.

  - A use after free in devtools.

  - A use after free in window management.

  - A use after free in V8.

  Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 81.0.4044.92." );
	script_tag( name: "solution", value: "Update to Google Chrome version
  81.0.4044.92 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2020/04/stable-channel-update-for-desktop_7.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "81.0.4044.92" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "81.0.4044.92", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

