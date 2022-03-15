CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809045" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5173", "CVE-2016-5174", "CVE-2016-5175", "CVE-2016-7549", "CVE-2016-5176" );
	script_bugtraq_id( 92942, 93160, 93234 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-09-15 11:32:52 +0530 (Thu, 15 Sep 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_13-2016-09)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple use after free errors in Blink.

  - An arbitrary Memory Read error in v8

  - An extension resource access error.

  - The popup is not correctly suppressed.

  - Not ensuring that the recipient of a certain IPC message is a valid
    RenderFrame or RenderWidget.

  - An improper SafeBrowsing protection mechanism.

  - The various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to corrupt memory, to bypass security,
  to reduce performance, to bypass the SafeBrowsing protection mechanism, to
  cause a denial of service and other unspecified impact." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 53.0.2785.113 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  53.0.2785.113 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/09/stable-channel-update-for-desktop_13.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "53.0.2785.113" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "53.0.2785.113" );
	security_message( data: report );
	exit( 0 );
}

