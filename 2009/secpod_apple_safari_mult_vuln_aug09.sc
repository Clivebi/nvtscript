CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900912" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-19 06:49:38 +0200 (Wed, 19 Aug 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2195", "CVE-2009-2196", "CVE-2009-2199", "CVE-2009-2200" );
	script_bugtraq_id( 36022, 36023, 36024, 36026 );
	script_name( "Apple Safari Multiple Vulnerabilities - Aug09" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT3733" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36269/" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2009/Aug/msg00002.html" );
	script_xref( name: "URL", value: "http://securethoughts.com/2009/08/hijacking-safari-4-top-sites-with-phish-bombs" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, gain sensitive information and can cause Denial of Service." );
	script_tag( name: "affected", value: "Apple Safari version prior to 4.0.3." );
	script_tag( name: "insight", value: "- An error in WebKit while parsing malicious floating point numbers can be
  exploited to cause buffer overflows.

  - An unspecified error in the Top Sites feature can be exploited to place a
  malicious  web site in the Top Sites view when a user visits a specially crafted web page.

  - Incomplete blacklist vulnerability in WebKit can be exploited via unspecified homoglyphs.

  - An error in WebKit in the handling of the 'pluginspage' attribute of the
  'embed' element can be exploited to launch arbitrary file: URLs and obtain
  sensitive information via a crafted HTML document." );
	script_tag( name: "solution", value: "Upgrade to Safari version 4.0.3." );
	script_tag( name: "summary", value: "This host is installed with Apple Safari Web Browser and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.31.9.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 4.0.3 (4.31.9.1)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

