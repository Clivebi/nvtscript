CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809074" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184", "CVE-2016-5185", "CVE-2016-5188", "CVE-2016-5189", "CVE-2016-5186", "CVE-2016-5191", "CVE-2016-5190", "CVE-2016-5194" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-10-21 12:32:32 +0530 (Fri, 21 Oct 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2016-10)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An universal XSS error in Blink

  - A heap overflow error in Blink.

  - Multiple use after free errors in PDFium.

  - An use after free error in Blink.

  - Multiple URL spoofing errors.

  - An UI spoofing error.

  - A cross-origin bypass error in Blink.

  - An out of bounds read error in DevTools.

  - An universal XSS error in Bookmarks.

  - An use after free error in Internals.

  - A scheme bypass error." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to bypass security, to execute
  arbitrary script code, to corrupt memory and to conduct spoofing attacks." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 54.0.2840.59 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  54.0.2840.59 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/10/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_is_less( version: chr_ver, test_version: "54.0.2840.59" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "54.0.2840.59" );
	security_message( data: report );
	exit( 0 );
}

