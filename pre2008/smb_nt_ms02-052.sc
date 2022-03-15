if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11177" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6371, 6372 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "IAVA", value: "2003-B-0002" );
	script_cve_id( "CVE-2002-1257", "CVE-2002-1258", "CVE-2002-1183", "CVE-2002-0862" );
	script_name( "Flaw in Microsoft VM Could Allow Code Execution (810030)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 SECNAP Network Security, LLC" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc", "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "Hotfix to fix Flaw in Microsoft VM
  could Allow Code Execution (810030)" );
	script_tag( name: "impact", value: "Three vulnerabilities, the most
  serious of which could enable an attacker to gain complete
  control over a user's system." );
	script_tag( name: "affected", value: "Versions of the Microsoft virtual machine (Microsoft VM) are
  identified by build numbers, which can be determined using the JVIEW tool as discussed in the FAQ.
  All builds of the Microsoft VM up to and including build 5.0.3805 are affected by these
  vulnerabilities." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-052" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-069" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has releases updates, please see the references for more information." );
	exit( 0 );
}
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
if(hotfix_check_sp( xp: 2, win2k: 4 ) <= 0){
	exit( 0 );
}
version = get_kb_item( "SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version" );
if(!version){
	exit( 0 );
}
v = split( buffer: version, sep: ",", keep: FALSE );
if(int( v[0] ) < 5 || ( int( v[0] ) == 5 && int( v[1] ) == 0 && int( v[2] ) < 3809 )){
	if(hotfix_missing( name: "810030" ) > 0){
		security_message( port: 0 );
	}
}

