if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11091" );
	script_version( "2020-06-09T11:16:08+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 11:16:08 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5480 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2002-0720" );
	script_name( "Windows Network Manager Privilege Elevation (Q326886)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 SECNAP Network Security, LLC" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "A flaw in the Windows 2000 Network Connection Manager
  could enable privilege elevation." );
	script_tag( name: "impact", value: "Elevation of Privilege." );
	script_tag( name: "affected", value: "Microsoft Windows 2000." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-042" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win2k: 4 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "Q326886" ) > 0){
	security_message( port: 0 );
}

