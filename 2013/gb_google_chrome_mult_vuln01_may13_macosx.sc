if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803706" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2013-2836", "CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839", "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843", "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847", "CVE-2013-2848", "CVE-2013-2849" );
	script_bugtraq_id( 60062, 60065, 60072, 60074, 60064, 60066, 60067, 60068, 60069, 60076, 60070, 60071, 60073, 60063 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-24 11:44:26 +0530 (Fri, 24 May 2013)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 May13 (MAC OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53430" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028588" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/05/stable-channel-release.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code or
  disclose sensitive information, conduct cross-site scripting attacks and
  compromise a users system." );
	script_tag( name: "affected", value: "Google Chrome version prior to 27.0.1453.93 on MAC OS X" );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 27.0.1453.93 or later." );
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
if(version_is_less( version: chromeVer, test_version: "27.0.1453.93" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "27.0.1453.93" );
	security_message( port: 0, data: report );
	exit( 0 );
}

