if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11808" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 8205 );
	script_cve_id( "CVE-2003-0352" );
	script_xref( name: "IAVA", value: "2003-A-0011" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Microsoft RPC Interface Buffer Overrun (823980)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 KK LIU" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "solution", value: "The vendor has releases updates, please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-012" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2005/ms05-012" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2005/ms05-051" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-018" );
	script_tag( name: "summary", value: "The remote host is running a version of Windows which has a flaw in
  its RPC interface which may allow an attacker to execute arbitrary code
  and gain SYSTEM privileges. There is at least one Worm which is
  currently exploiting this vulnerability. Namely, the MsBlaster worm." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( xp: 3, win2k: 5, win2003: 2 ) <= 0){
	exit( 0 );
}
rollUp = registry_key_exists( key: "SOFTWARE\\Microsoft\\Updates\\Windows 2000\\SP5\\Update Rollup 1" );
if(rollUp){
	exit( 0 );
}
if(hotfix_missing( name: "828741" ) == 0 || hotfix_missing( name: "873333" ) == 0 || hotfix_missing( name: "902400" ) == 0 || hotfix_missing( name: "913580" ) == 0){
	exit( 0 );
}
if(hotfix_missing( name: "823980" ) == 1){
	security_message( port: get_kb_item( "SMB/transport" ) );
	exit( 0 );
}
exit( 99 );

