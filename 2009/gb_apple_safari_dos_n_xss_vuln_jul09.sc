CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800834" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2009-07-12 15:16:55 +0200 (Sun, 12 Jul 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1724", "CVE-2009-1725" );
	script_bugtraq_id( 35441, 35607 );
	script_name( "Apple Safari DoS or XSS Vulnerability - July09" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT3666" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2009/Jul/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code and can
  cause memory corruption, XSS attacks and can deny the service in the victim's system." );
	script_tag( name: "affected", value: "Apple Safari version prior to 4.0.2 on Windows." );
	script_tag( name: "insight", value: "- Error in 'WebKit' is allow user to inject arbitrary web script or HTML via
  vectors related to parent and top objects.

  - Error in 'WebKit' is fails to handle numeric character references via a
  crafted HTML document." );
	script_tag( name: "solution", value: "Upgrade to Safari version 4.0.2 (4.30.19.1)." );
	script_tag( name: "summary", value: "This host is installed with Apple Safari Web Browser and is prone to Denial
  of Service or Cross-Site Scripting vulnerability." );
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
if(version_is_less( version: vers, test_version: "4.30.19.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 4.0.2 (4.30.19.1)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

