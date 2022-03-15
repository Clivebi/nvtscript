if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94242" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.338: Einsatz von File und Registry Virtualization bei Clients ab Windows Vista" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04338.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/EL15/GSHB_WMI_UAC_config.sc" );
	script_require_keys( "WMI/UAC" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.338: Einsatz von File und Registry Virtualization bei Clients ab Windows Vista.

Stand: 15. Ergänzungslieferung (15. EL).

Hinweis:
Nur ein genereller Test, ob Vista File und Registry Virtualization aktiviert ist." );
	exit( 0 );
}
require("itg.inc.sc");
name = "M4.338: Einsatz von File und Registry Virtualization bei Clients ab Windows Vista\n";
gshbm = "IT-Grundschutz M4.338: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
EnableVirtualization = get_kb_item( "WMI/EnableVirtualization" );
EnableLUA = get_kb_item( "WMI/EnableLUA" );
UAC = get_kb_item( "WMI/UAC" );
log = get_kb_item( "WMI/UAC/log" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba, es ist kein Microsoft System." );
}
else {
	if( ContainsString( "error", UAC ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( OSVER >= "6.0" && OSTYPE == "1" ){
			if( EnableLUA != "1" ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "User Access Control ist auf dem System deaktiviert, dadurch ist\\nauch die Vista File und Registry Virtualization deaktiviert." );
			}
			else {
				if( EnableVirtualization == "1" ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Vista File und Registry Virtualization ist aktiviert. Beachten\nSie bitte die Hinweise im IT-Grundschutz-Katalog zur\nMaßnahme 4.338" );
				}
				else {
					result = NASLString( "erfüllt" );
					desc = NASLString( "Vista File und Registry Virtualization ist deaktiviert.\\nBeachten Sie bitte die Hinweise im IT-Grundschutz-Katalog zur\\nMaßnahme 4.338" );
				}
			}
		}
		else {
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Microsoft Windows System größer gleich Windows Vista." );
		}
	}
}
set_kb_item( name: "GSHB/M4_338/result", value: result );
set_kb_item( name: "GSHB/M4_338/desc", value: desc );
set_kb_item( name: "GSHB/M4_338/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_338" );
}
exit( 0 );

