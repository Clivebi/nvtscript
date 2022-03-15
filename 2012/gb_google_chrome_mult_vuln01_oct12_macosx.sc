if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802472" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-2900", "CVE-2012-5108", "CVE-2012-5109", "CVE-2012-5110", "CVE-2012-5111" );
	script_bugtraq_id( 55830 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-10-15 12:25:07 +0530 (Mon, 15 Oct 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 Oct12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50872/" );
	script_xref( name: "URL", value: "https://www.securelist.com/en/advisories/50872" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/10/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to execute arbitrary code
  with the privileges of a local user and cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 22.0.1229.92 on Mac OS X" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - A race condition error exists related to audio device handling.

  - An error exists related to Skia text rendering, ICU regex, compositor
    handling and plug-in crash monitoring for Pepper plug-ins." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 22.0.1229.92 or later." );
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
if(version_is_less( version: chromeVer, test_version: "22.0.1229.92" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "22.0.1229.92" );
	security_message( port: 0, data: report );
}

