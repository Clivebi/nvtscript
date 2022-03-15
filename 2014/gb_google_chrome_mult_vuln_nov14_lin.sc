CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804894" );
	script_version( "2021-08-11T09:52:19+0000" );
	script_cve_id( "CVE-2014-7900", "CVE-2014-7901", "CVE-2014-7902", "CVE-2014-7903", "CVE-2014-7904", "CVE-2014-7906", "CVE-2014-7907", "CVE-2014-7908", "CVE-2014-7909", "CVE-2014-7910", "CVE-2014-7899" );
	script_bugtraq_id( 71163, 71158, 71165, 71164, 71166, 71159, 71170, 71168, 71167, 71161, 71160 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 09:52:19 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-11-25 18:55:43 +0530 (Tue, 25 Nov 2014)" );
	script_name( "Google Chrome Multiple Vulnerabilities - 01 November14 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A use-after-free error in pdfium.

  - An integer overflow error in pdfium.

  - Another use-after-free error in pdfium.

  - An unspecified error in pdfium.

  - An unspecified error in Skia.

  - A use-after-free error in pepper plugins.

  - Multiple use-after-free errors in blink.

  - An integer overflow error in media.

  - An unspecified error in Skia.

  - Other Multiple unspecified errors.

  - An unspecified error that can be exploited to spoof the address bar." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose potentially sensitive information, conduct spoofing attacks,
  bypass certain security restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Google Chrome version prior to 39.0.2171.65
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 39.0.2171.65
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62546" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/11/stable-channel-update_18.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "39.0.2171.65" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "39.0.2171.65" );
	security_message( port: 0, data: report );
	exit( 0 );
}

