if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802451" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-2869", "CVE-2012-2868", "CVE-2012-2867", "CVE-2012-2866", "CVE-2012-2865", "CVE-2012-2872", "CVE-2012-2871", "CVE-2012-2870" );
	script_bugtraq_id( 55331 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-09-03 14:01:42 +0530 (Mon, 03 Sep 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities - Sep12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50447" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55331" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/08/stable-channel-update_30.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 21.0.1180.89 on Windows" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Out-of-bounds read in line breaking

  - Bad cast with run-ins.

  - Browser crash with SPDY.

  - Race condition with workers and XHR.

  - Avoid stale buffer in URL loading.

  - Lower severity memory management issues in XPath

  - Bad cast in XSL transforms.

  - XSS in SSL interstitial." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 21.0.1180.89 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "21.0.1180.89" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "21.0.1180.89" );
	security_message( port: 0, data: report );
}

