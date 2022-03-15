if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10964" );
	script_version( "2020-06-09T11:16:08+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 11:16:08 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4287 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2002-0367" );
	script_name( "Windows Debugger flaw can Lead to Elevated Privileges (Q320206)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Michael Scheidell" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "Authentication Flaw in Windows Debugger can Lead to Elevated
  Privileges (Q320206)" );
	script_tag( name: "impact", value: "Elevation of Privilege." );
	script_tag( name: "affected", value: "- Microsoft Windows NT 4.0

  - Microsoft Windows NT 4.0 (Server, Terminal Server Edition)

  - Microsoft Windows 2000" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-024" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( nt: 7, win2k: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "Q320206" ) > 0){
	security_message( port: 0 );
}

