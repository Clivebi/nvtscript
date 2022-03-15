if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902057" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)" );
	script_cve_id( "CVE-2010-1688" );
	script_bugtraq_id( 40311 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "SyncBack Profile Import Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39865" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58727" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "insight", value: "The flaw exists due to boundary error when importing 'SyncBack' profiles,
  which leads to stack-based buffer overflow when a user opens a specially
  crafted '.sps' file." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the SyncBack Freeware version 3.2.21" );
	script_tag( name: "summary", value: "This host is installed with SyncBack Freeware and is prone
  to buffer overflow vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "SyncBack Freeware version prior to 3.2.21" );
	script_xref( name: "URL", value: "http://www.2brightsparks.com/downloads.html#freeware" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" + "\\SyncBack_is1";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
syncName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( syncName, "SyncBack" )){
	syncPath = registry_get_sz( key: key, item: "InstallLocation" );
	if(!isnull( syncPath )){
		exePath = syncPath + "\\SyncBack.exe";
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
		fire = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath );
		syncVer = GetVer( file: fire, share: share );
		if(syncVer != NULL){
			if(version_is_less( version: syncVer, test_version: "3.2.21.0" )){
				report = report_fixed_ver( installed_version: syncVer, fixed_version: "3.2.21.0", install_path: exePath );
				security_message( port: 0, data: report );
			}
		}
	}
}

