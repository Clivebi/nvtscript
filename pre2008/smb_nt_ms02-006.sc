if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10865" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0053" );
	script_name( "Checks for MS HOTFIX for snmp buffer overruns" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 Michael Scheidell" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "There is an Unchecked Buffer in SNMP Service and this
  checks to see if the Microsoft Patch has been applied (only checks NT/Win2k and XP Pro)." );
	script_tag( name: "impact", value: "Run code of attacker's choice and denial of service attacks.

  Also may run snmp detect to see if snmp is running on this host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-006" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( nt: 7, win2k: 3, xp: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "Q314147" ) > 0){
	security_message( port: 0 );
}

