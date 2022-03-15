if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11143" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4881 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-0368" );
	script_name( "Exchange 2000 Exhaust CPU Resources (Q320436)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 Michael Scheidell" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "summary", value: "Malformed Mail Attribute can Cause Exchange 2000 to Exhaust CPU
  Resources (Q320436)" );
	script_tag( name: "impact", value: "Denial of Service." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-025" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
server = hotfix_check_nt_server();
if(!server){
	exit( 0 );
}
vers = hotfix_check_exchange_installed();
if(vers == NULL){
	exit( 0 );
}
if(hotfix_missing( name: "320436" ) > 0){
	security_message( port: 0 );
}

