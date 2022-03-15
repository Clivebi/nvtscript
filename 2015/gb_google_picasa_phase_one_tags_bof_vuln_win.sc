CPE = "cpe:/a:google:picasa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806628" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-8096" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-11-26 12:49:36 +0530 (Thu, 26 Nov 2015)" );
	script_name( "Google Picasa 'Phase One Tags' Buffer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Google Picasa
  and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an integer overflow
  error when processing data related to phase one 0x412 tag." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Google Picasa versions 3.9.140 build 239
  and Build 248" );
	script_tag( name: "solution", value: "Upgrade to Google Picasa version 3.9.141
  build 259 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2015-3" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/134084" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/536761/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_google_picasa_detect_win.sc" );
	script_mandatory_keys( "Google/Picasa/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!picVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: picVer, test_version: "3.9.140.239" ) || version_is_equal( version: picVer, test_version: "3.9.140.248" )){
	report = "Installed Version: " + picVer + "\n" + "Fixed Version:     3.9.141 build 259  \n";
	security_message( data: report );
	exit( 0 );
}

