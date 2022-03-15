if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94246" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.341: Integritätsschutz ab Windows Vista" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04341.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/EL15/GSHB_WMI_UAC_config.sc", "GSHB/GSHB_WMI_ProtectedMode.sc" );
	script_require_keys( "WMI/UAC" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.341: Integritätsschutz ab Windows Vista.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Soweit technisch möglich umgesetzt (aktiviertes UAC und geschützter Modus in verschiedenen Zonen)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.341: Integritätsschutz ab Windows Vista\n";
gshbm = "IT-Grundschutz M4.341: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
ProtModeIntraZone = get_kb_item( "WMI/ProtModeIntraZone" );
ProtModeInterZone = get_kb_item( "WMI/ProtModeInterZone" );
ProtModeRestrZone = get_kb_item( "WMI/ProtModeRestrZone" );
EnableLUA = get_kb_item( "WMI/EnableLUA" );
UAC = get_kb_item( "WMI/UAC" );
log = get_kb_item( "WMI/ProtMode/log" );
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
				desc = NASLString( "User Access Control ist auf dem System deaktiviert,\\ndadurch ist auch der Geschützte Modus des Internet\\nExplorers deaktiviert." );
			}
			else {
				if( ProtModeIntraZone != "0" || ProtModeInterZone != "0" || ProtModeRestrZone != "0" ){
					result = NASLString( "nicht erfüllt" );
					if(ProtModeIntraZone != "0"){
						desc = NASLString( "Der Geschützte Modus wurde für den IE in der Zone\nLokales Intranet nicht wie gefordert konfiguriert.\n" );
					}
					if(ProtModeInterZone != "0"){
						desc += NASLString( "Der Geschützte Modus wurde für den IE in der Zone\nInternet nicht wie gefordert konfiguriert.\n" );
					}
					if(ProtModeRestrZone != "0"){
						desc += NASLString( "Der Geschützte Modus wurde für den IE in der Zone\nEingeschränkte Sites nicht wie gefordert konfiguriert.\n" );
					}
				}
				else {
					result = NASLString( "erfüllt" );
					desc = NASLString( "\\nDer konfigurierbare Teil des Systems entspricht der\\nIT-Grundschutz Maßnahme 4.341" );
				}
			}
		}
		else {
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Microsoft Windows System größer gleich Windows Vista." );
		}
	}
}
set_kb_item( name: "GSHB/M4_341/result", value: result );
set_kb_item( name: "GSHB/M4_341/desc", value: desc );
set_kb_item( name: "GSHB/M4_341/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_341" );
}
exit( 0 );

