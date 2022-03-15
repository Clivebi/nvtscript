if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109033" );
	script_version( "$Revision: 10647 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:07:45 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2017-12-06 09:20:21 +0100 (Wed, 06 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Read the config of the User Account Control feature over SMB" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc", "smb_reg_service_pack.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "Read the config of the User Account Control feature over SMB from Registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
OSVER = get_kb_item( "SMB/WindowsVersion" );
if(OSVER < "6.0"){
	set_kb_item( name: "SMB/UAC", value: "error" );
	set_kb_item( name: "SMB/UAC/log", value: "Can not get access to the host. Can not perform test on those systems." );
	exit( 0 );
}
FilterAdministratorToken = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "FilterAdministratorToken" );
ConsentPromptBehaviorAdmin = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "ConsentPromptBehaviorAdmin" );
ConsentPromptBehaviorUser = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "ConsentPromptBehaviorUser" );
EnableInstallerDetection = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "EnableInstallerDetection" );
ValidateAdminCodeSignatures = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "ValidateAdminCodeSignatures" );
EnableLUA = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "EnableLUA" );
PromptOnSecureDesktop = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "PromptOnSecureDesktop" );
EnableVirtualization = registry_get_dword( key: "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", item: "EnableVirtualization" );
set_kb_item( name: "SMB/UAC/FilterAdministratorToken", value: FilterAdministratorToken );
set_kb_item( name: "SMB/UAC/ConsentPromptBehaviorAdmin", value: ConsentPromptBehaviorAdmin );
set_kb_item( name: "SMB/UAC/ConsentPromptBehaviorUser", value: ConsentPromptBehaviorUser );
set_kb_item( name: "SMB/UAC/EnableInstallerDetection", value: EnableInstallerDetection );
set_kb_item( name: "SMB/UAC/ValidateAdminCodeSignatures", value: ValidateAdminCodeSignatures );
set_kb_item( name: "SMB/UAC/EnableLUA", value: EnableLUA );
set_kb_item( name: "SMB/UAC/PromptOnSecureDesktop", value: PromptOnSecureDesktop );
set_kb_item( name: "SMB/UAC/EnableVirtualization", value: EnableVirtualization );
set_kb_item( name: "SMB/UAC", value: "success" );
exit( 0 );

