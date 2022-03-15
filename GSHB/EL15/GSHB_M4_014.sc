if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94181" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04014.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_SSH_passwords.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.014: Obligatorischer Passwortschutz unter Unix\n";
gshbm = "IT-Grundschutz M4.014: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
SHADOW = get_kb_item( "GSHB/etc_shadow" );
NoPWUser = get_kb_item( "GSHB/NoPWUser" );
PWUser = get_kb_item( "GSHB/PWUser" );
SunPasswd = get_kb_item( "GSHB/SunPasswd" );
LOG = get_kb_item( "GSHB/etc_shadow/log" );
Testdays = "180";
if( !ContainsString( "none", OSVER ) ){
	OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( SHADOW == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( LOG ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Beim Testen des Systems ist ein Fehler aufgetreten:\n" + LOG );
		}
		else {
			if( PWUser != "none" || NoPWUser != "none" ){
				User = split( buffer: PWUser, sep: ";", keep: 0 );
				for(i = 0;i < max_index( User );i++){
					val = split( buffer: User[i], sep: ":", keep: 0 );
					if(int( val[1] ) > int( Testdays )){
						Failuser += "\nUser: " + val[0] + ", zuletzt geändert vor " + val[1] + " Tagen";
					}
				}
				if( !ContainsString( "none", NoPWUser ) || Failuser ){
					result = NASLString( "nicht erfüllt" );
					if(!ContainsString( "none", NoPWUser )){
						desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass\nfolgende Benutzer kein Passwort haben:\n" + NoPWUser );
					}
					if(Failuser){
						desc += NASLString( "\nBeim Testen des Systems wurde festgestellt, dass\nfolgende User ihr Passwort seit über " + Testdays + "\\nTagen nicht geändert haben:" + Failuser );
					}
				}
				else {
					if( ContainsString( "noperm", SunPasswd ) ){
						result = NASLString( "Fehler" );
						desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass die\nBerechtigung nicht reicht um \"passwd -sa\" auszuführen." );
					}
					else {
						result = NASLString( "Fehler" );
						desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf." );
					}
				}
			}
			else {
				if( SHADOW == "nopermission" && PWUser == "none" && NoPWUser == "none" ){
					result = NASLString( "unvollständig" );
					desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass der\nTestbenutzer keine Berechtigung hat den Befehl passwd\nauszuführen. Alternativ wurde versucht, die Datei\n/etc/shadow zu lesen. Bitte prüfen Sie manuell ob die\nUser der Maßnahme M4.014 entsprechen." );
				}
				else {
					if(SHADOW == "noshadow" && PWUser == "none" && NoPWUser == "none"){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass die\nDatei /etc/shadow anscheinend nicht vorhanden ist,\nbzw. nicht genutzt wird." );
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_014/result", value: result );
set_kb_item( name: "GSHB/M4_014/desc", value: desc );
set_kb_item( name: "GSHB/M4_014/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_014" );
}
exit( 0 );

