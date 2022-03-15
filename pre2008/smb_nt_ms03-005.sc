if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11231" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6778 );
	script_cve_id( "CVE-2003-0004" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Unchecked Buffer in XP Redirector (Q810577)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2003 SECNAP Network Security" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "The remote host is vulnerable to a flaw in the RPC redirector." );
	script_tag( name: "impact", value: "This flaw could allow a local attacker to run code of its choice
  with the SYSTEM privileges." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-005" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( xp: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "810577" ) > 0 && hotfix_missing( name: "885835" ) > 0){
	security_message( port: 0 );
}

