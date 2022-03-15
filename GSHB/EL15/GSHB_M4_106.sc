if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94214" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04106.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_SSH_syslog.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung\n";
gshbm = "IT-Grundschutz M4.106: ";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
var_log = get_kb_item( "GSHB/var_log" );
var_adm = get_kb_item( "GSHB/var_adm" );
syslog = get_kb_item( "GSHB/syslog" );
rsyslog = get_kb_item( "GSHB/rsyslog" );
syslogr = get_kb_item( "GSHB/syslogr" );
rsyslogr = get_kb_item( "GSHB/rsyslogr" );
log = get_kb_item( "GSHB/rsyslog/log" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( rsyslog == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( ContainsString( "error", rsyslog ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein\nunbekannter Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
		else {
			if( ( IsMatchRegexp( var_log, "d......r...*" ) || IsMatchRegexp( var_adm, "d......r...*" ) ) || ( IsMatchRegexp( syslogr, "........w..*" ) || IsMatchRegexp( rsyslogr, "........w..*" ) ) ){
				result = NASLString( "nicht erfüllt" );
				if( IsMatchRegexp( var_log, "d......r...*" ) && IsMatchRegexp( var_adm, "d......r...*" ) ) {
					desc = NASLString( "Für die Verzeichnisse /var/log und /var/adm sind\nöffentliche Leserechte eingestellt, bitte ändern Sie\ndas:" + "\n/var/log: " + var_log + "\n/var/adm: " + var_adm );
				}
				else {
					if( IsMatchRegexp( var_log, "d......r...*" ) ) {
						desc = NASLString( "Für das Verzeichnis /var/log sind öffentliche\nLeserechte eingestellt, bitte ändern Sie das:\n/var/log: " + var_log );
					}
					else {
						if(IsMatchRegexp( var_adm, "d......r...*" )){
							desc = NASLString( "Für das Verzeichnis /var/adm sind öffentliche\nLeserechte eingestellt, bitte ändern Sie das:\n/var/adm: " + var_adm );
						}
					}
				}
				if( IsMatchRegexp( syslogr, "........w..*" ) || IsMatchRegexp( rsyslogr, "........w..*" ) ) {
					desc += NASLString( "\nFür die Dateien /etc/syslog.conf und /etc/rsyslog.conf\nsind öffentliche Schreibrechte eingestellt, bitte\nändern Sie das:\n/etc/syslog.conf: " + syslogr + "\n/etc/rsyslog.conf: " + rsyslogr );
				}
				else {
					if( IsMatchRegexp( syslogr, "........w..*" ) ) {
						desc += NASLString( "\nFür die Datei /etc/syslog.conf sind öffentliche\nSchreibrechte eingestellt, bitte ändern Sie das:\n/etc/syslog.conf: " + syslogr );
					}
					else {
						if(IsMatchRegexp( rsyslogr, "........w..*" )){
							desc += NASLString( "\nFür die Datei /etc/rsyslog.conf sind öffentliche\nSchreibrechte eingestellt, bitte ändern Sie das:\n/etc/rsyslog.conf: " + rsyslogr );
						}
					}
				}
			}
			else {
				if( ( syslog == "none" && rsyslog == "norights" ) || ( rsyslog == "none" && syslog == "norights" ) || ( syslog == "norights" && rsyslog == "norights" ) ){
					result = NASLString( "unvollständig" );
					if( syslog == "norights" && rsyslog == "norights" ) {
						desc = NASLString( "Sie haben kein Berechtigung die Dateien\n/etc/syslog.conf und /etc/rsyslog.conf zu lesen." );
					}
					else {
						if( rsyslog == "norights" ) {
							desc = NASLString( "Sie haben kein Berechtigung die Datei\n/etc/rsyslog.conf zu lesen." );
						}
						else {
							if(syslog == "norights"){
								desc = NASLString( "Sie haben kein Berechtigung die Datei\n/etc/syslog.conf zu lesen." );
							}
						}
					}
				}
				else {
					if( ( syslog == "none" && syslog == "off" ) && ( rsyslog == "none" && rsyslog == "off" ) ){
						result = NASLString( "Fehler" );
						desc = NASLString( "Die Dateien /etc/syslog.conf und /etc/rsyslog.conf\nwurden nicht gefunden." );
					}
					else {
						result = NASLString( "unvollständig" );
						desc = NASLString( "Die Berechtigungen für /etc/var, /etc/log,\n/etc/syslog.conf bzw. /etc/rsyslog.conf sind korrekt\ngesetzt.\nBitte prüfen Sie ob unten angegebenen\nParameter aus" );
						if( syslog != "none" && syslog != "off" ){
							Lst = split( buffer: syslog, keep: 0 );
							for(i = 0;i < max_index( Lst );i++){
								if(Lst[i] == ""){
									continue;
								}
								parameter += Lst[i] + "\n";
							}
							desc += NASLString( " der Datei /etc/syslog.conf,\ndenen der Maßnahme 4.106 entsprechen.\n" + parameter );
						}
						else {
							if(rsyslog != "none" && rsyslog != "off"){
								Lst = split( buffer: rsyslog, keep: 0 );
								for(i = 0;i < max_index( Lst );i++){
									if(Lst[i] == ""){
										continue;
									}
									parameter += Lst[i] + "\n";
								}
								desc += NASLString( " der Datei /etc/rsyslog.conf,\ndenen der Maßnahme 4.106 entsprechen.\n" + parameter );
							}
						}
					}
				}
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( " Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_106/result", value: result );
set_kb_item( name: "GSHB/M4_106/desc", value: desc );
set_kb_item( name: "GSHB/M4_106/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_106" );
}
exit( 0 );

