CPE = "cpe:/a:apple:quicktime";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804053" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_cve_id( "CVE-2010-1819" );
	script_bugtraq_id( 42774 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-12-31 12:44:42 +0530 (Tue, 31 Dec 2013)" );
	script_name( "Apple QuickTime Pictureviewer Arbitrary Code Execution Vulnerability Dec13 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple QuickTime and is prone to code execution
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Apple QuickTime version 7.6.8 or later." );
	script_tag( name: "insight", value: "Flaw is due to the PictureViewer application loading libraries
  (e.g. CoreGraphics.dll) in an insecure manner." );
	script_tag( name: "affected", value: "Apple QuickTime version before 7.6.8 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code and
  compromise a vulnerable system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4339" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41123" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2010/Sep/msg00003.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_quicktime_detection_win_900124.sc" );
	script_mandatory_keys( "QuickTime/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.68.75.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.68.75.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

