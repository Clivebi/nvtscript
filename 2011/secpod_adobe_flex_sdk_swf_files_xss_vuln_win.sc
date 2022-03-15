if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902765" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-2461" );
	script_bugtraq_id( 50869 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-13 00:49:37 +0530 (Tue, 13 Dec 2011)" );
	script_name( "Adobe Flex SDK 'SWF' Files Cross-Site Scripting Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50869/info" );
	script_xref( name: "URL", value: "http://kb2.adobe.com/cps/915/cpsid_91544.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-25.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Adobe Flex SDK version 3.x through 3.6 and 4.x through 4.5.1" );
	script_tag( name: "insight", value: "The flaw is due to certain unspecified input passed to SWF files developed
  using the framework is not properly sanitised before being returned to the user." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flex SDK and is prone to
  cross site scripting vulnerability." );
	script_tag( name: "solution", value: "Apply the patch." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	flexName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( flexName, "Adobe Flex" )){
		sdkPath = registry_get_sz( key: key + item, item: "FrameworkPath" );
		if(ContainsString( sdkPath, "sdk" )){
			sdkVer = eregmatch( pattern: "\\\\([0-9.]+)", string: sdkPath );
			if(!isnull( sdkVer[1] )){
				if(version_in_range( version: sdkVer[1], test_version: "3.0", test_version2: "3.6" ) || version_in_range( version: sdkVer[1], test_version: "4.0", test_version2: "4.5.1" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

