if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802262" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)" );
	script_cve_id( "CVE-2011-2845", "CVE-2011-3875", "CVE-2011-3876", "CVE-2011-3877", "CVE-2011-3878", "CVE-2011-3879", "CVE-2011-3880", "CVE-2011-3881", "CVE-2011-3882", "CVE-2011-3883", "CVE-2011-3884", "CVE-2011-3885", "CVE-2011-3886", "CVE-2011-3887", "CVE-2011-3888", "CVE-2011-3889", "CVE-2011-3890", "CVE-2011-3891" );
	script_bugtraq_id( 50360 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Google Chrome Multiple Vulnerabilities - October11 (Windows)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026242" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/10/chrome-stable-release.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code,
  steal cookie-based authentication credentials, bypass the cross-origin
  restrictions, perform spoofing attacks, and disclose potentially sensitive
  information, other attacks may also be possible." );
	script_tag( name: "affected", value: "Google Chrome version prior to 15.0.874.102 on Windows" );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 15.0.874.102 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "15.0.874.102" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "15.0.874.102" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

