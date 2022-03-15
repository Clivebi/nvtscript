if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900046" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)" );
	script_bugtraq_id( 31067 );
	script_cve_id( "CVE-2008-3007" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows : Microsoft Bulletins" );
	script_name( "Microsoft Office Remote Code Execution Vulnerabilities (955047)" );
	script_dependencies( "secpod_ms_office_detection_900025.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Ver" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-055" );
	script_tag( name: "summary", value: "This host is missing critical security update according to
  Microsoft Bulletin MS08-055." );
	script_tag( name: "insight", value: "The issue is due to an error in the parsing of a URI using
  the onenote:// protocol handler." );
	script_tag( name: "affected", value: "Microsoft Office XP/2003/2007." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "impact", value: "Remote attackers could be able to execute arbitrary code
  via a specially crafted OneNote URI referencing a specially crafted One Note file." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3 ) <= 0){
	exit( 0 );
}
prgmDir = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!prgmDir){
	exit( 0 );
}
offVer = get_kb_item( "MS/Office/Ver" );
if(!offVer){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^10\\." )){
	dllPath = prgmDir + "\\Common Files\\Microsoft Shared\\Office10\\MSO.DLL";
	vers = get_version( dllPath: dllPath );
	if(!vers){
		exit( 0 );
	}
	if(egrep( pattern: "^10\\.0\\.([0-5]?[0-9]?[0-9]?[0-9]|6([0-7][0-9][0-9]|8([0-3][0-9]|4[0-4])))$", string: vers )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "10.0.6845", file_checked: dllPath );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	exit( 99 );
}
if(IsMatchRegexp( offVer, "^11\\." )){
	dllPath = prgmDir + "\\Common Files\\Microsoft Shared\\Office11\\MSO.DLL";
	vers = get_version( dllPath: dllPath );
	if(!vers){
		exit( 0 );
	}
	if(egrep( pattern: "^11\\.0\\.([0-7]?[0-9]?[0-9]?[0-9]|8([01][0-9][0-9]|2[01][0-9]|220))$", string: vers )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "11.0.8221", file_checked: dllPath );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	exit( 99 );
}
if(IsMatchRegexp( offVer, "^12\\." )){
	dllPath = prgmDir + "\\Common Files\\Microsoft Shared\\Office12\\MSO.DLL";
	vers = get_version( dllPath: dllPath );
	if(!vers){
		exit( 0 );
	}
	if(egrep( pattern: "^12\\.0\\.([0-5].*|62.*|63[01][0-9].*|6320\\.[0-4]?[0-9]?[0-9]?[0-9])$", string: vers )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "12.0.6320.5000", file_checked: dllPath );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

