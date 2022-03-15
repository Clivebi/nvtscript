if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94250" );
	script_version( "$Revision: 14124 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 08:14:43 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.368: Regelm��ige Audits der Terminalserver-Umgebung" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "GSHB/GSHB_WMI_TerminalServerSettings.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04368.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.368: Regelm��ige Audits der Terminalserver-Umgebung.

  Stand: 14. Erg�nzungslieferung (14. EL).

  Hinweis: Es wird lediglich ein Meldung ausgegeben, dass mit aktuelleten Plugins getestet werden soll." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("itg.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M4.368: Regelm��ige Audits der Terminalserver-Umgebung\n";
gshbm = "GSHB Ma�nahme 4.368: ";
SAMBA = kb_smb_is_samba();
TSS = get_kb_item( "WMI/TerminalService" );
log = get_kb_item( "WMI/TerminalService/log" );
OSVER = get_kb_item( "WMI/WMI_OSVER" );
if(TSS != "error" && TSS != "none"){
	val = split( buffer: TSS, keep: 0 );
	val = split( buffer: val[1], sep: "|", keep: 0 );
}
if( SAMBA ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Das System ist kein Windows Terminal Server. (Zur Zeit kann nur auf Windows Terminal Server getestet werden.)" );
}
else {
	if( !TSS ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Bei Testen des Systems konnte kein Ergebnis ermittelt werden." );
	}
	else {
		if( ( OSVER != "none" && OSVER != "error" ) && TSS == "error" ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( ( OSVER != "none" && OSVER != "error" ) && TSS == "none" ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Das System ist kein Windows Terminal Server. (Zur Zeit kann nur auf Windows Terminal Server getestet werden.)" );
			}
			else {
				if( TSS == "error" ){
					result = NASLString( "Fehler" );
					if(!log){
						desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
					}
					if(log){
						desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
					}
				}
				else {
					if( val[11] == "2" || val[11] == "4" || val[11] == "5" ){
						result = NASLString( "unvollst�ndig" );
						desc = NASLString( "F�hren Sie bitte eine Pr�fung Ihres Netzwerkes mit dem aktuellen NVT-Set aus." );
					}
					else {
						result = NASLString( "nicht zutreffend" );
						desc = NASLString( "Das System ist kein Windows Terminal Server. (Zur Zeit kann nur auf Windows Terminal Server getestet werden.)" );
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_368/result", value: result );
set_kb_item( name: "GSHB/M4_368/desc", value: desc );
set_kb_item( name: "GSHB/M4_368/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_368" );
}
exit( 0 );

