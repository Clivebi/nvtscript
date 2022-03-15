if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109998" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-09 09:12:10 +0100 (Mon, 09 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.2.2.2.A12" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_2_Clients_unter_Windows_8_1.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc", "Policy/WindowsGeneral/NetworkSecurity/win_nsec_encryption_types_kerberos.sc", "Policy/WindowsGeneral/NetworkSecurity/win_nsec_store_lanman_hash_passwd.sc", "Policy/WindowsGeneral/AdvancedAudit/win_logon.sc", "Policy/WindowsGeneral/AdvancedAudit/win_other_logon_logoff.sc", "Policy/WindowsGeneral/AdvancedAudit/win_special_logon.sc", "Policy/WindowsGeneral/SCM/win_lsa_protection.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.2.2.2 ist der Schutz von Informationen,
die durch und auf Windows 8.1-Clients verarbeiten werden.

Die Standard-Anforderung 'A12: Zentrale Authentifizierung in Windows-Netzen' beschreibt, wie die zentrale
Authentifizierung in Windows-Netzen konfiguriert sein sollte." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Standard" )){
	exit( 0 );
}
title = "Zentrale Authentifizierung in Windows-Netzen";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration/Windows Settings/Local Policies/Security Options/Network security: Configure encryption types allowed for Kerberos,
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/Network security: Do not store LAN Manager hash value on next password change,
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audi tPolicies/Logon / Logoff/Audit Logon,
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audi tPolicies/Logon / Logoff/Audit Other Logon/Logoff Events,
Computer Configuration/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Audi tPolicies/Logon / Logoff/Audit Special Logon,
HKLM/SYSTEM/CurrentControlSet/Control/Lsa!RunAsPPL";
oid_list = make_list( "1.3.6.1.4.1.25623.1.0.109232",
	 "1.3.6.1.4.1.25623.1.0.109233",
	 "1.3.6.1.4.1.25623.1.0.109587",
	 "1.3.6.1.4.1.25623.1.0.109588",
	 "1.3.6.1.4.1.25623.1.0.109589",
	 "1.3.6.1.4.1.25623.1.0.109605" );
if(os_host_runs( "windows_8.1" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A12" );
	exit( 0 );
}
results_list = itg_get_policy_control_result( oid_list: oid_list );
result = itg_translate_result( compliant: results_list["compliant"] );
report = policy_build_report( result: "MULTIPLE", default: "MULTIPLE", compliant: results_list["compliant"], fixtext: results_list["solutions"], type: "MULTIPLE", test: results_list["tests"], info: results_list["notes"] );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A12" );
itg_report( report: report );
exit( 0 );

