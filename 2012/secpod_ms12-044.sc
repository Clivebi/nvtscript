if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902686" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-1522", "CVE-2012-1524" );
	script_bugtraq_id( 54293, 54294 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-07-11 09:42:59 +0530 (Wed, 11 Jul 2012)" );
	script_name( "Microsoft Internet Explorer Multiple Vulnerabilities (2719177)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2719177" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1027226" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-044" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 9.x." );
	script_tag( name: "insight", value: "Multiple vulnerabilities are due to the way that Internet Explorer
  accesses an object that has been deleted." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-044." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win2008: 3, win7: 2 ) <= 0){
	exit( 0 );
}
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer || !IsMatchRegexp( ieVer, "^9\\." )){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Mshtml.dll" );
if(!dllVer){
	exit( 0 );
}
if(version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16446" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20552" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

