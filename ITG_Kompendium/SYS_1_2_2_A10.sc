if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150018" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-13 10:19:13 +0100 (Fri, 13 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.1.2.2.A10" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_2_2_Windows_Server_2012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc", "Policy/WindowsGeneral/WindowsComponents/win_hw_based_os_drive_encryption.sc", "Policy/WindowsGeneral/WindowsComponents/win_os_software_enc_failover.sc", "Policy/WindowsGeneral/WindowsComponents/win_os_restrict_encryption.sc", "Policy/WindowsGeneral/WindowsComponents/win_os_bitlocker_require_ad_backup.sc", "Policy/WindowsGeneral/WindowsComponents/win_addauth_tpm_startup_pin.sc", "Policy/WindowsGeneral/WindowsComponents/win_addauth_bitlocker_no_tpm.sc", "Policy/WindowsGeneral/WindowsComponents/win_secure_boot_integrityval.sc", "Policy/WindowsGeneral/WindowsComponents/win_hardware_based_encryption.sc", "Policy/WindowsGeneral/WindowsComponents/win_hw_encryption_restrict_crypto.sc", "Policy/WindowsGeneral/WindowsComponents/win_hw_encryption_restrict_algorithms.sc", "Policy/WindowsGeneral/WindowsComponents/win_bitlocker_require_ad_backup.sc", "Policy/WindowsGeneral/WindowsComponents/win_hw_based_encryption_rm.sc", "Policy/WindowsGeneral/WindowsComponents/win_hw_rm_restrict_encryption.sc", "Policy/WindowsGeneral/WindowsComponents/win_hw_based_enc_rm_failover.sc", "Policy/WindowsGeneral/WindowsComponents/win_rm_bitlocker_recovery_require_ad.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.1.2.2 ist die Absicherung von Microsoft
Windows Server 2012 und Microsoft Windows Server 2012 R2.

Die Kern-Anforderung 'A10: Festplattenverschluesselung bei Windows Server 2012' beschreibt, dass
Festplatten verschluesselt sein sollten." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Kern" )){
	exit( 0 );
}
title = "Festplattenverschluesselung bei Windows Server 2012";
desc = "Folgende Einstellungen werden getestet:
Windows Components/BitLocker Drive Encryption/Operating System Drives/Configure use of hardware-based encryption for operating system drives,
Windows Components/BitLocker Drive Encryption/Operating System Drives/Configure use of hardware-based encryption for operating system drives (software encryption failover),
Windows Components/BitLocker Drive Encryption/Operating System Drives/Configure use of hardware-based encryption for operating system drives (restrict algorithms),
Windows Components/BitLocker Drive Encryption/Operating System Drives/Configure use of hardware-based encryption for operating system drives (require AD backup),
Windows Components/BitLocker Drive Encryption/Operating System Drives/Require additional authentication at startup,
Windows Components/BitLocker Drive Encryption/Operating System Drives/Require additional authentication at startup (BitLocker without TPM),
Windows Components/BitLocker Drive Encryption/Operating System Drives/Allow Secure Boot for integrity validation,
Windows Components/BitLocker Drive Encryption/Fixed Data Drives/Configure use of hardware-based encryption for fixed data drives,
Windows Components/BitLocker Drive Encryption/Fixed Data Drives/Configure use of hardware-based encryption for fixed data drives (Allowed crypto algorithms),
Windows Components/BitLocker Drive Encryption/Fixed Data Drives/Configure use of hardware-based encryption for fixed data drives (Restrict crypto algorithms),
Windows Components/BitLocker Drive Encryption/Fixed Data Drives/Configure use of hardware-based encryption for fixed data drives (require AD backup),
Windows Components/BitLocker Drive Encryption/Removable Data Drives/Configure use of hardware-based encryption for removable data drives,
Windows Components/BitLocker Drive Encryption/Removable Data Drives/Configure use of hardware-based encryption for removable data drives (restrict algorithms),
Windows Components/BitLocker Drive Encryption/Removable Data Drives/Configure use of hardware-based encryption for removable data drives (software encryption failover),
Windows Components/BitLocker Drive Encryption/Removable Data Drives/Configure use of hardware-based encryption for removable data drives (require AD backup)";
oid_list = make_list( "1.3.6.1.4.1.25623.1.0.109398",
	 "1.3.6.1.4.1.25623.1.0.109399",
	 "1.3.6.1.4.1.25623.1.0.109400",
	 "1.3.6.1.4.1.25623.1.0.109396",
	 "1.3.6.1.4.1.25623.1.0.109406",
	 "1.3.6.1.4.1.25623.1.0.109404",
	 "1.3.6.1.4.1.25623.1.0.109388",
	 "1.3.6.1.4.1.25623.1.0.109379",
	 "1.3.6.1.4.1.25623.1.0.109382",
	 "1.3.6.1.4.1.25623.1.0.109381",
	 "1.3.6.1.4.1.25623.1.0.109378",
	 "1.3.6.1.4.1.25623.1.0.109418",
	 "1.3.6.1.4.1.25623.1.0.109420",
	 "1.3.6.1.4.1.25623.1.0.109419",
	 "1.3.6.1.4.1.25623.1.0.109417" );
if(os_host_runs( "windows_server_2012" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.2.2.A10" );
	exit( 0 );
}
results_list = itg_get_policy_control_result( oid_list: oid_list );
result = itg_translate_result( compliant: results_list["compliant"] );
report = policy_build_report( result: "MULTIPLE", default: "MULTIPLE", compliant: results_list["compliant"], fixtext: results_list["solutions"], type: "MULTIPLE", test: results_list["tests"], info: results_list["notes"] );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.2.2.A10" );
itg_report( report: report );
exit( 0 );

