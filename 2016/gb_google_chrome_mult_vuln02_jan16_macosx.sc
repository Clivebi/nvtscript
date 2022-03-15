CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806667" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-1612", "CVE-2016-1613", "CVE-2016-1614", "CVE-2016-1615", "CVE-2016-1616", "CVE-2016-1617", "CVE-2016-1618", "CVE-2016-1619", "CVE-2016-1620", "CVE-2016-2051", "CVE-2016-2052" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-01-22 14:58:05 +0530 (Fri, 22 Jan 2016)" );
	script_name( "Google Chrome Multiple Vulnerabilities-02 Jan16 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Bad cast in V8.

  - Use-after-free error in PDFium.

  - Information leak error in Blink.

  - Origin confusion error in Omnibox.

  - URL Spoofing.

  - History sniffing with HSTS and CSP.

  - Weak random number generator in Blink.

  - Out-of-bounds read in PDFium.

  - Multiple Other Vulnerabilities.

  - Other Unspecified Vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation would allow a remote
  attacker to conduct URL spoofing attacks, bypass certain security restrictions,
  gain access to sensitive information, cause a denial of service condition or
  possibly have unspecified other impact." );
	script_tag( name: "affected", value: "Google Chrome versions prior to 48.0.2564.82
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  48.0.2564.82 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/01/stable-channel-update_20.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "48.0.2564.82" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     48.0.2564.82" + "\n";
	security_message( data: report );
	exit( 0 );
}

