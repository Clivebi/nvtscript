if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802881" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-2815", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2822", "CVE-2012-2823", "CVE-2012-2824", "CVE-2012-2825", "CVE-2012-2826", "CVE-2012-2828", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2832", "CVE-2012-2833", "CVE-2012-2834" );
	script_bugtraq_id( 54203 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-07-04 14:54:30 +0530 (Wed, 04 Jul 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities - July 12 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49724" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/06/stable-channel-update_26.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 20.0.1132.43 on Linux" );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 20.0.1132.43 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "20.0.1132.43" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "20.0.1132.43" );
	security_message( port: 0, data: report );
}

