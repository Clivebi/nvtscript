if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109992" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-09 09:12:10 +0100 (Mon, 09 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.2.2.2.A6" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_2_Clients_unter_Windows_8_1.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc", "Policy/WindowsDefenderAV/defav_turn_off_defender.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.2.2.2 ist der Schutz von Informationen,
die durch und auf Windows 8.1-Clients verarbeiten werden.

Die Standard-Anforderung 'A6: Datei- und Freigabeberechtigungen' beschreibt, dass ein Berechtigungs- und
Zugriffskonzept fuer Windows vorhanden sein sollte." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Standard" )){
	exit( 0 );
}
title = "Datei- und Freigabeberechtigungen";
if(os_host_runs( "windows_8.1" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A6" );
	exit( 0 );
}
desc = itg_no_automatic_test();
result = itg_no_automatic_test();
report = policy_build_report( result: result, default: "None", compliant: "yes", fixtext: "None", type: "None", test: "None", info: desc );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A6" );
itg_report( report: report );
exit( 0 );

