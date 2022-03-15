if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800570" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1612" );
	script_bugtraq_id( 34789 );
	script_name( "BaoFeng Storm ActiveX Control Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/8579" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34944" );
	script_xref( name: "URL", value: "http://bbs.baofeng.com/read.php?tid=121630" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Attacker may exploit this issue to execute arbitrary script code and may cause
  denial of service." );
	script_tag( name: "affected", value: "BaoFeng Storm mps.dll version 3.9.4.27 and prior on Windows." );
	script_tag( name: "insight", value: "A boundary error in the MPS.StormPlayer.1 ActiveX control (mps.dll) while
  processing overly large argument passed to the 'OnBeforeVideoDownload()'
  method leads to buffer overflow." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest BaoFeng Storm version 3.9.05.10." );
	script_tag( name: "summary", value: "This host is installed with BaoFeng Storm ActiveX and is prone to
  Buffer Overflow vulnerability." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
stormPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\Uninstall\\Storm2", item: "DisplayIcon" );
if(!stormPath){
	exit( 0 );
}
stormPath = stormPath - "Storm.exe" + "mps.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: stormPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: stormPath );
stormdllVer = GetVer( share: share, file: file );
if(stormdllVer != NULL){
	if(version_is_less_equal( version: stormdllVer, test_version: "3.9.4.27" )){
		report = report_fixed_ver( installed_version: stormdllVer, vulnerable_range: "Less than or equal to 3.9.4.27", install_path: stormPath );
		security_message( port: 0, data: report );
	}
}

