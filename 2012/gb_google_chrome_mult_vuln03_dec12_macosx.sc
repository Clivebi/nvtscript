if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803129" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-5139", "CVE-2012-5140", "CVE-2012-5141", "CVE-2012-5142", "CVE-2012-5143", "CVE-2012-5144" );
	script_bugtraq_id( 56903 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-12-14 13:40:56 +0530 (Fri, 14 Dec 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities-03 Dec2012 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51549/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/12/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 23.0.1271.97 on Mac OS X" );
	script_tag( name: "insight", value: "- An use-after-free error exists in visibility events and in URL loader.

  - Error exists within the instantiation of the Chromoting client plug-in,
    history navigation and AAC decoding.

  - An integer overflow error exists within handling of PPAPI image buffers." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 23.0.1271.97 or later." );
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
if(version_is_less( version: chromeVer, test_version: "23.0.1271.97" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "23.0.1271.97" );
	security_message( port: 0, data: report );
}

