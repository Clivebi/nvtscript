if(description){
	script_version( "2021-04-16T06:57:08+0000" );
	script_oid( "1.3.6.1.4.1.25623.1.0.150584" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 09:31:46 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_name( "SYS.1.3.A4" );
	script_category( ACT_GATHER_INFO );
	script_family( "IT-Grundschutz" );
	script_dependencies( "os_detection.sc", "compliance_tests.sc", "Policy/Linux/Setup/aslr_status.sc", "Policy/Linux/Setup/xdnx_support.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Kompendium_Einzel_PDFs_2021/07_SYS_IT_Systeme/SYS_1_3_Server_unter_Linux_und_Unix_Edition_2021.pdf?__blob=publicationFile&v=3" );
	script_tag( name: "summary", value: "Um die Ausnutzung von Schwachstellen in Anwendungen zu erschweren,
MUSS ASLR und DEP/NX im Kernel aktiviert und von den Anwendungen genutzt werden.
Sicherheitsfunktionen des Kernels und der Standardbibliotheken, wie z. B. Heap- und Stackschutz,
DUERFEN NICHT deaktiviert werden." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Basis" )){
	exit( 0 );
}
title = "Schutz vor Ausnutzung von Schwachstellen in Anwendungen";
desc = "Folgende Einstellungen werden getestet:
ALSR ist aktiviert.
XD/NX ist aktiviert.";
oid_list = make_list( "1.3.6.1.4.1.25623.1.0.109737",
	 "1.3.6.1.4.1.25623.1.0.109736" );
if(os_host_runs( "linux" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.3.A4" );
	exit( 0 );
}
results_list = itg_get_policy_control_result( oid_list: oid_list );
result = itg_translate_result( compliant: results_list["compliant"] );
report = policy_build_report( result: "MULTIPLE", default: "MULTIPLE", compliant: results_list["compliant"], fixtext: results_list["solutions"], type: "MULTIPLE", test: results_list["tests"], info: results_list["notes"] );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.3.A4" );
itg_report( report: report );
exit( 0 );

