if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94245" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.340: Einsatz der Windows Benutzerkontensteuerung UAC ab Windows Vista" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04340.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/EL15/GSHB_WMI_UAC_config.sc" );
	script_require_keys( "WMI/UAC" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.340: Einsatz der Windows Benutzerkontensteuerung UAC ab Windows Vista.

Stand: 15. Ergänzungslieferung (15. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.340: Einsatz der Windows Benutzerkontensteuerung UAC ab Windows Vista\n";
gshbm = "IT-Grundschutz M4.340: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
ConsentPromptBehaviorAdmin = get_kb_item( "WMI/ConsentPromptBehaviorAdmin" );
ConsentPromptBehaviorUser = get_kb_item( "WMI/ConsentPromptBehaviorUser" );
EnableLUA = get_kb_item( "WMI/EnableLUA" );
UAC = get_kb_item( "WMI/UAC" );
log = get_kb_item( "WMI/UAC/log" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
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
				desc = NASLString( "User Access Control ist auf dem System deaktiviert" );
			}
			else {
				if( ConsentPromptBehaviorAdmin != "0" || ConsentPromptBehaviorUser != "1" ){
					result = NASLString( "nicht erfüllt" );
					if(ConsentPromptBehaviorAdmin != "0"){
						desc = NASLString( "Der Registry Wert für ConsentPromptBehaviorAdmin ist\nnicht wie gefordert -0-!\n" );
					}
					if(ConsentPromptBehaviorUser != "1"){
						desc += NASLString( "Der Registry Wert für ConsentPromptBehaviorUser ist\nnicht wie gefordert -1-!\n" );
					}
				}
				else {
					result = NASLString( "erfüllt" );
					desc = NASLString( "Das System Entspricht der IT-Grundschutz\\nMaßnahme M4.340." );
				}
			}
		}
		else {
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Microsoft Windows System größer gleich Windows Vista." );
		}
	}
}
set_kb_item( name: "GSHB/M4_340/result", value: result );
set_kb_item( name: "GSHB/M4_340/desc", value: desc );
set_kb_item( name: "GSHB/M4_340/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_340" );
}
exit( 0 );

