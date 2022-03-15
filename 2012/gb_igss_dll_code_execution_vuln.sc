if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802297" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2011-4053" );
	script_bugtraq_id( 51438 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-01-23 15:15:15 +0530 (Mon, 23 Jan 2012)" );
	script_name( "Interactive Graphical SCADA System DLL Loading Arbitrary Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51438" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICSA-11-353-01.pdf" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_igss_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "IGSS/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "7T Interactive Graphical SCADA System (IGSS) versions prior to 9.0.0.11291" );
	script_tag( name: "insight", value: "This flaw is due to the application insecurely loading certain
  libraries from the current working directory, which could allow attackers
  to execute arbitrary code by tricking a user into opening a file from a
  network share." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with Interactive Graphical SCADA System
  and is prone to code execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.7t.dk/igss/igssupdates/v90/progupdatesv90.zip" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
version = get_kb_item( "IGSS/Win/Ver" );
if(!version){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "9.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^9\\.0\\.*" )){
	key = "SOFTWARE\\7-Technologies\\IGSS32\\v9.00.00\\ENVIRONMENT";
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
	odbcPath = registry_get_sz( key: key, item: "IGSSWORK" );
	if(!odbcPath){
		exit( 0 );
	}
	odbcVer = fetch_file_version( sysPath: odbcPath, file_name: "Odbcixv9se.exe" );
	if(!odbcVer){
		exit( 0 );
	}
	if(version_is_less( version: version, test_version: "9.0.0.11291" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.0.0.11291", install_path: odbcPath );
		security_message( port: 0, data: report );
	}
}

