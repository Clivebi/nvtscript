if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802919" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-2842", "CVE-2012-2843", "CVE-2012-2844" );
	script_bugtraq_id( 54386 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-07-24 12:06:53 +0530 (Tue, 24 Jul 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities(01) - July 12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49906" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027249" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/07/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 20.0.1132.57 on Mac OS X" );
	script_tag( name: "insight", value: "- A use-after-free error exists within counter handling and within layout
    height tracking.

  - An unspecified error when handling JavaScript within PDFs can be
    exploited to access certain objects." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 20.0.1132.57 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
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
if(version_is_less( version: chromeVer, test_version: "20.0.1132.57" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "20.0.1132.57" );
	security_message( port: 0, data: report );
}

