CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807352" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-5141", "CVE-2016-5142", "CVE-2016-5139", "CVE-2016-5140", "CVE-2016-5145", "CVE-2016-5143", "CVE-2016-5144", "CVE-2016-5146" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-04 15:10:25 +0530 (Thu, 04 Aug 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2016-08)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An address bar spoofing vulnerability.

  - An use-after-free error in Blink.

  - Multiple heap overflow errors in pdfium.

  - A same origin bypass error for images in Blink.

  - Parameter sanitization failure in DevTools.

  - The various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to conduct spoofing attacks on a
  targeted system, to bypass security, to corrupt memory, to execute arbitrary
  code and to cause denial of service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to
  52.0.2743.116 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  52.0.2743.116 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/08/stable-channel-update-for-desktop.html" );
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
if(version_is_less( version: chr_ver, test_version: "52.0.2743.116" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "52.0.2743.116" );
	security_message( data: report );
	exit( 0 );
}

