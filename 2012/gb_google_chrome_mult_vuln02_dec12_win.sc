if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803121" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-5138", "CVE-2012-5137" );
	script_bugtraq_id( 56741 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-12-04 12:37:33 +0530 (Tue, 04 Dec 2012)" );
	script_name( "Google Chrome Multiple Vulnerabilities-02 Dec2012 (Windows)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56741" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/11/stable-channel-update_29.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 23.0.1271.95 on Windows" );
	script_tag( name: "insight", value: "- A use-after-free error exists in media source handling.

  - An incorrect file path handling, Does not properly handle file paths." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 23.0.1271.95 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "23.0.1271.95" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "23.0.1271.95" );
	security_message( port: 0, data: report );
}

