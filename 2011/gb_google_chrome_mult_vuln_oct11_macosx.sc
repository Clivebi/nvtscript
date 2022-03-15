if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802256" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)" );
	script_cve_id( "CVE-2011-2876", "CVE-2011-2877", "CVE-2011-2878", "CVE-2011-2879", "CVE-2011-2880", "CVE-2011-2881", "CVE-2011-3873" );
	script_bugtraq_id( 49938 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Google Chrome multiple vulnerabilities - October11 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46308/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, cause denial-of-service conditions and bypass
  the same-origin policy." );
	script_tag( name: "affected", value: "Google Chrome version prior to 14.0.835.202 on Mac OS X" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A use-after-free error exists in text line box handling.

  - An error in the SVG text handling can be exploited to reference a stale
    font.

  - An error exists within cross-origin access handling associated with a
    window prototype.

  - Some errors exist within audio node handling related to lifetime and
    threading.

  - A use-after-free error exists in the v8 bindings.

  - An error when handling v8 hidden objects can be exploited to corrupt memory.

  - An error in the shader translator can be exploited to corrupt memory." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 14.0.835.202 or later." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
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
if(version_is_less( version: chromeVer, test_version: "14.0.835.202" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "14.0.835.202" );
	security_message( port: 0, data: report );
}

