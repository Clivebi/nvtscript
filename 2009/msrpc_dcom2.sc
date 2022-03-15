if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102015" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-11-16 11:47:06 +0100 (Mon, 16 Nov 2009)" );
	script_cve_id( "CVE-2003-0715", "CVE-2003-0528", "CVE-2003-0605" );
	script_bugtraq_id( 8458, 8460 );
	script_xref( name: "IAVA", value: "2003-A-0012" );
	script_xref( name: "OSVDB", value: "2535" );
	script_xref( name: "OSVDB", value: "11460" );
	script_xref( name: "OSVDB", value: "11797" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft RPC Interface Buffer Overrun (KB824146)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 LSS" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "solution", value: "The vendor has released updates, please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-039" );
	script_tag( name: "summary", value: "The remote host is running a version of Windows which has a flaw in
  its RPC interface which may allow an attacker to execute arbitrary code
  and gain SYSTEM privileges." );
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
if(hotfix_missing( name: "824146" ) == 1){
	security_message( port: 0 );
	exit( 0 );
}
exit( 99 );

