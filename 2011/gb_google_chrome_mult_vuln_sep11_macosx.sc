if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802328" );
	script_version( "2021-08-11T13:58:23+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 13:58:23 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)" );
	script_cve_id( "CVE-2011-2821", "CVE-2011-2823", "CVE-2011-2824", "CVE-2011-2825", "CVE-2011-2826", "CVE-2011-2827", "CVE-2011-2828", "CVE-2011-2829" );
	script_bugtraq_id( 49279 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Google Chrome multiple vulnerabilities - September11 (Mac OS X)" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/08/stable-channel-update_22.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security restrictions, or cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 13.0.782.215 on Mac OS X." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple use-after-free errors exist within the handling of features like
  line boxes, counter nodes, custom fonts and text searching.

  - A double free error exists in libxml when handling XPath expression.

  - An error related to empty origins allows attackers to violate the
  cross-origin policy.

  - An integer overflow error in uniform arrays." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 13.0.782.215 or later." );
	script_tag( name: "summary", value: "The host is running Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/MacOSX/Version" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "13.0.782.215" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "13.0.782.215" );
	security_message( port: 0, data: report );
}

