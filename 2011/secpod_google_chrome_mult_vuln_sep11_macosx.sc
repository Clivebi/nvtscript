if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902629" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)" );
	script_cve_id( "CVE-2011-2834", "CVE-2011-2835", "CVE-2011-2836", "CVE-2011-2838", "CVE-2011-2839", "CVE-2011-2840", "CVE-2011-2841", "CVE-2011-2843", "CVE-2011-2844", "CVE-2011-2846", "CVE-2011-2847", "CVE-2011-2848", "CVE-2011-2849", "CVE-2011-2850", "CVE-2011-2851", "CVE-2011-2852", "CVE-2011-2853", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2856", "CVE-2011-2857", "CVE-2011-2858", "CVE-2011-2859", "CVE-2011-2860", "CVE-2011-2861", "CVE-2011-2862", "CVE-2011-2864", "CVE-2011-2874", "CVE-2011-2875", "CVE-2011-3234", "CVE-2011-2842", "CVE-2011-2830" );
	script_bugtraq_id( 49658 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Google Chrome Multiple Vulnerabilities - Sep11 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46049" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/09/stable-channel-update_16.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 14.0.835.163 on Mac OS X." );
	script_tag( name: "insight", value: "For more information on the vulnerabilities refer to the links below." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 14.0.835.163 or later." );
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
if(version_is_less( version: chromeVer, test_version: "14.0.835.163" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "14.0.835.163" );
	security_message( port: 0, data: report );
}

