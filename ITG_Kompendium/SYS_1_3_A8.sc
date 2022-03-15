if(description){
	script_version( "2021-04-16T06:57:08+0000" );
	script_oid( "1.3.6.1.4.1.25623.1.0.150587" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 09:31:46 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_name( "SYS.1.3.A8" );
	script_category( ACT_GATHER_INFO );
	script_family( "IT-Grundschutz" );
	script_dependencies( "os_detection.sc", "compliance_tests.sc", "Policy/Linux/Services/rsh_server.sc", "Policy/Linux/Services/talk_server.sc", "Policy/Linux/Services/telnet_server.sc", "Policy/Linux/AccesAndAuth/sshd_passwordauthentications.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Kompendium_Einzel_PDFs_2021/07_SYS_IT_Systeme/SYS_1_3_Server_unter_Linux_und_Unix_Edition_2021.pdf?__blob=publicationFile&v=3" );
	script_tag( name: "summary", value: "Um eine verschluesselte und authentisierte, interaktive
Verbindung zwischen zwei IT-Systemen aufzubauen, SOLLTE ausschliesslich Secure Shell (SSH) verwendet
werden. Alle anderen Protokolle, deren Funktionalitaet durch Secure Shell abgedeckt wird, SOLLTEN
vollstaendig abgeschaltet werden. Fuer die Authentifizierung SOLLTEN Benutzer vorrangig Zertifikate
anstatt eines Passwortes verwenden." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Standard" )){
	exit( 0 );
}
title = "Verschluesselter Zugriff ueber Secure Shell";
desc = "Folgende Einstellungen werden getestet:
Services rsh, talk und telnet sind deaktiviert.
PasswordAuthentication ist deaktiviert in der Datei /etc/ssh/sshd_config.";
oid_list = make_list( "1.3.6.1.4.1.25623.1.0.150514",
	 "1.3.6.1.4.1.25623.1.0.150513",
	 "1.3.6.1.4.1.25623.1.0.150512",
	 "1.3.6.1.4.1.25623.1.0.150321" );
if(os_host_runs( "linux" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.3.A8" );
	exit( 0 );
}
results_list = itg_get_policy_control_result( oid_list: oid_list );
result = itg_translate_result( compliant: results_list["compliant"] );
report = policy_build_report( result: "MULTIPLE", default: "MULTIPLE", compliant: results_list["compliant"], fixtext: results_list["solutions"], type: "MULTIPLE", test: results_list["tests"], info: results_list["notes"] );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.3.A8" );
itg_report( report: report );
exit( 0 );

