if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802932" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2012-2862", "CVE-2012-2863" );
	script_bugtraq_id( 54897 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-08-14 17:03:39 +0530 (Tue, 14 Aug 2012)" );
	script_name( "Google Chrome PDF Viewer Multiple Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50222/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2012/08/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 21.0.1180.75 on Windows" );
	script_tag( name: "insight", value: "Use-after-free and out-of-bounds write errors exist within the PDF viewer." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 21.0.1180.75 or later." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to use after
  free and denial of service vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "21.0.1180.75" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "21.0.1180.75" );
	security_message( port: 0, data: report );
}

