if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900029" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)" );
	script_bugtraq_id( 30598, 30595, 30597, 30599, 30600 );
	script_cve_id( "CVE-2008-3018", "CVE-2008-3019", "CVE-2008-3020", "CVE-2008-3021", "CVE-2008-3460" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows : Microsoft Bulletins" );
	script_name( "Microsoft Office Filters Could Allow Remote Code Execution Vulnerabilities (924090)" );
	script_dependencies( "smb_reg_service_pack.sc", "secpod_ms_office_detection_900025.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Ver" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-044" );
	script_tag( name: "summary", value: "This host is missing critical security update according to
  Microsoft Bulletin MS08-044." );
	script_tag( name: "insight", value: "Multiple flaws due to memory corruption errors when processing
  specially crafted Encapsulated PostScript (EPS) files, and PICT, BMP, or WordPerfect Graphics (WPG) images." );
	script_tag( name: "affected", value: "- Microsoft Office 2k SP3

  - Microsoft Office XP Service Pack 3

  - Microsoft Office 2003 Service Pack 2

  - Microsoft Office Project 2002 Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "impact", value: "Remote exploitation could allow attackers to execute
  arbitrary code by tricking a user into opening a malicious office file, and also can
  crash an affected application." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
if(!get_kb_item( "MS/Office/Ver" )){
	exit( 0 );
}
gifPath = registry_get_sz( item: "Path", key: "SOFTWARE\\Microsoft\\Shared Tools\\Graphics Filters\\Export\\GIF" );
if(!gifPath){
	exit( 0 );
}
gifVer = get_version( dllPath: gifPath, string: "prod", offs: 16500 );
if(!gifVer){
	exit( 0 );
}
if(egrep( pattern: "^([01]?[0-9]?[0-9]?[0-9]\\..*|200[0-2]\\..*|2003\\.([0-9]?[0-9]?" + "[0-9]\\..*|10[0-9][0-9]\\..*|1100\\.([0-7]?[0-9]?[0-9]?[0-9]|80" + "[0-9][0-9]|81[0-5][0-9]|816[0-4])))$", string: gifVer )){
	security_message( port: 0 );
}

