if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902785" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0007" );
	script_bugtraq_id( 51291 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "creation_date", value: "2012-01-11 13:30:24 +0530 (Wed, 11 Jan 2012)" );
	script_name( "Microsoft AntiXSS Library Information Disclosure Vulnerability (2607664)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026499" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-007" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to bypass the filter and
  conduct cross-site scripting attacks. Successful exploits may allow attackers
  to execute arbitrary script code and steal cookie-based authentication
  credentials." );
	script_tag( name: "affected", value: "- Microsoft Anti-Cross Site Scripting Library version 3.x

  - Microsoft Anti-Cross Site Scripting Library version 4.0" );
	script_tag( name: "insight", value: "The flaw is due to error in library which fails to properly filter
  HTML code from user-supplied input. A remote user may be able to exploit a
  target application that uses the library to cause arbitrary scripting code to
  be executed by the target user's browser." );
	script_tag( name: "solution", value: "Upgrade to Microsoft Anti-Cross Site Scripting Library version 4.2.1" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-007." );
	script_tag( name: "qod_type", value: "registry" );
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
	xssName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( xssName, "Microsoft AntiXSS" ) || ContainsString( xssName, "Microsoft Anti-Cross Site Scripting Library" )){
		xssVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(xssVer){
			if(IsMatchRegexp( xssVer, "^3\\.*" ) || version_in_range( version: xssVer, test_version: "4.0", test_version2: "4.2.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

