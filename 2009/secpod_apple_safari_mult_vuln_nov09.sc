CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900889" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2816", "CVE-2009-2842", "CVE-2009-3384" );
	script_bugtraq_id( 36997, 36994, 36995 );
	script_name( "Apple Safari Multiple Vulnerabilities - Nov09" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to bypass certain security
  restrictions, disclose sensitive information, or compromise a user's system." );
	script_tag( name: "affected", value: "Apple Safari version prior to 4.0.4." );
	script_tag( name: "insight", value: "- An error exists in WebKit when sending 'preflight' requests originating
  from a page in a different origin. This can be exploited to facilitate
  cross-site request forgery attacks by injecting custom HTTP headers.

  - An error exists when handling an 'Open Image in New Tab', 'Open Image in'
  'New Window', or 'Open Link in New Tab' shortcut menu action performed on
  a link to a local file. This can be exploited to load a local HTML file
  and disclose sensitive information by tricking a user into performing the
  affected actions within a specially crafted webpage.

  - Multiple errors in WebKit when handling FTP directory listings can be
  exploited to disclose sensitive information." );
	script_tag( name: "solution", value: "Upgrade to Safari version 4.0.4 or latest version." );
	script_tag( name: "summary", value: "This host has Apple Safari installed and is prone to multiple
  vulnerabilities." );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT3949" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37346" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2009/Nov/msg00001.html" );
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
if(version_is_less( version: vers, test_version: "5.31.21.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 4.0.4 (5.31.21.11)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

