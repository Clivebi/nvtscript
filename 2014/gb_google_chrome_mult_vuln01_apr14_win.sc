CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804548" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719", "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723", "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727", "CVE-2014-1728", "CVE-2014-1729" );
	script_bugtraq_id( 66704 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-22 12:53:01 +0530 (Tue, 22 Apr 2014)" );
	script_name( "Google Chrome Multiple Vulnerabilities - 01 Apr14 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A use-after-free error exists within 'web workers', 'DOM', 'forms' and 'speech'.

  - An unspecified error exists when handling URLs containing 'RTL' characters.

  - An integer overflow error exists within 'compositor'.

  - An error when handling certain 'window property'.

  - An unspecified error within 'V8'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct cross-site
scripting attacks, bypass certain security restrictions, and compromise
a user's system." );
	script_tag( name: "affected", value: "Google Chrome version prior to 34.0.1847.116 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome 34.0.1847.116 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57506" );
	script_xref( name: "URL", value: "http://threatpost.com/google-patches-31-flaws-in-chrome/105326" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/04/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "34.0.1847.116" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "34.0.1847.116" );
	security_message( port: 0, data: report );
	exit( 0 );
}

