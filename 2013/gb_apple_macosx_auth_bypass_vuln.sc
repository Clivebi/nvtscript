if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804184" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-5163" );
	script_bugtraq_id( 62812 );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-12-31 20:51:30 +0530 (Tue, 31 Dec 2013)" );
	script_name( "Apple Mac OS X Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and is prone to authentication bypass
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Run Mac Updates and install OS X v10.8.5 Supplemental Update." );
	script_tag( name: "insight", value: "The flaw is due to a logic error in the way the program verifies
authentication credentials." );
	script_tag( name: "affected", value: "Mac OS X version 10.8.5 and prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow a local attacker to bypass password
validation." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5964" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/123506/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.8" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5964" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(ContainsString( osName, "Mac OS X" )){
	if(version_in_range( version: osVer, test_version: "10.8.0", test_version2: "10.8.5" )){
		report = report_fixed_ver( installed_version: osVer, vulnerable_range: "10.8.0 - 10.8.5" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

