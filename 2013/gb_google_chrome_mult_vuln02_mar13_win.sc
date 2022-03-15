if(description){
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code
  with higher privileges, corrupt memory, processing of databases outside
  a restricted origin path." );
	script_tag( name: "affected", value: "Google Chrome versions prior to 25.0.1364.152 on Windows" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Use-after-free error exists in Frame loader, Browser navigation handling,
    SVG animations.

  - Unknown error exists in Web Audio, Indexed DB, Handling of bindings for
    extension processes, Loading browser plug-in.

  - Race condition error exists in media thread handling.

  - Path traversal error exists when handling database.

  - Origin identifier is not properly sanitized during database handling." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 25.0.1364.152 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_oid( "1.3.6.1.4.1.25623.1.0.803432" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-0902", "CVE-2013-0903", "CVE-2013-0904", "CVE-2013-0905", "CVE-2013-0906", "CVE-2013-0907", "CVE-2013-0908", "CVE-2013-0909", "CVE-2013-0910", "CVE-2013-0911" );
	script_bugtraq_id( 58291 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-03-11 13:55:17 +0530 (Mon, 11 Mar 2013)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Google Chrome Multiple Vulnerabilities-02 March 2013 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/52454" );
	script_xref( name: "URL", value: "https://chromiumcodereview.appspot.com/12212091" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/03/stable-channel-update_4.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "25.0.1364.152" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "25.0.1364.152" );
	security_message( port: 0, data: report );
	exit( 0 );
}

