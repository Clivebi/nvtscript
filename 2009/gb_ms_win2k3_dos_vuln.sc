if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800577" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2008-6819" );
	script_bugtraq_id( 35121 );
	script_name( "Microsoft Windows Server 2003 win32k.sys DoS Vulnerability" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/35121.c" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow attakers to cause denial of
  service by crashing the operating system." );
	script_tag( name: "affected", value: "Microsoft Windows 2003 Service Pack 2 and prior." );
	script_tag( name: "insight", value: "The vulnerability lies in win32k.sys file and can be exploited
  via vectors related to CreateWindow, TranslateMessage and DispatchMessage
  functions to cause a race condition between threads." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Windows Server 2003 operating system and
  is prone to Denial of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3 ) <= 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(!sysPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sysPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sysPath + "\\Win32k.sys" );
sysVer = GetVer( file: file, share: share );
if(!sysVer){
	exit( 0 );
}
SP = get_kb_item( "SMB/Win2003/ServicePack" );
if( ContainsString( SP, "Service Pack 1" ) ){
	if(version_is_less_equal( version: sysVer, test_version: "5.2.3790.3291" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
else {
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less_equal( version: sysVer, test_version: "5.2.3790.4456" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

