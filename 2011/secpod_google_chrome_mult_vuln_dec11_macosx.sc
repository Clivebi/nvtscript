if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902646" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3903", "CVE-2011-3904", "CVE-2011-3905", "CVE-2011-3906", "CVE-2011-3907", "CVE-2011-3908", "CVE-2011-3909", "CVE-2011-3910", "CVE-2011-3911", "CVE-2011-3912", "CVE-2011-3913", "CVE-2011-3914", "CVE-2011-3915", "CVE-2011-3916", "CVE-2011-3917" );
	script_bugtraq_id( 51041 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-15 16:18:22 +0530 (Thu, 15 Dec 2011)" );
	script_name( "Google Chrome Multiple Vulnerabilities - December11 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47231/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51041" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/12/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Google Chrome versions prior to 16.0.912.63 on Mac OS X" );
	script_tag( name: "insight", value: "For more information on the vulnerabilities refer to the links below." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 16.0.912.63 or later." );
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
if(version_is_less( version: chromeVer, test_version: "16.0.912.63" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "16.0.912.63" );
	security_message( port: 0, data: report );
}

