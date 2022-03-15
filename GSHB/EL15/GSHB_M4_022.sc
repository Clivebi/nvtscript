if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94193" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.022: Verhinderung des Vertraulichkeitsverlusts schutzbedürftiger Daten im Unix-System" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04022.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_prev_sensitive_data_loss.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.022: Verhinderung des Vertraulichkeitsverlusts schutzbedürftiger Daten im Unix-System.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.022: Verhinderung des Vertraulichkeitsverlusts schutzbedürftiger Daten im Unix-System\n";
gshbm = "IT-Grundschutz M4.022: ";
ps = get_kb_item( "GSHB/ps" );
finger = get_kb_item( "GSHB/finger" );
who = get_kb_item( "GSHB/who" );
last = get_kb_item( "GSHB/last" );
tmpfiles = get_kb_item( "GSHB/tmpfiles" );
log = get_kb_item( "GSHB/ps/log" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( ps == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if(ContainsString( "error", ps )){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein unbekannter\nFehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
	}
}
if(result != "nicht zutreffend" && result != "Fehler"){
	if(ps == "none" || finger == "none" || who == "none" || last == "none" || tmpfiles == "none"){
		if(ps == "none"){
			result_ps = NASLString( "Fehler" );
			if(result_ps != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /bin/ps nicht gefunden werden konnte.\n" );
			}
		}
		if(finger == "none"){
			result_finger = NASLString( "Fehler" );
			if(result_finger != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /usr/bin/finger nicht gefunden\nwerden konnte.\n" );
			}
		}
		if(who == "none"){
			result_finger = NASLString( "Fehler" );
			if(result_finger != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /usr/bin/who nicht gefunden\nwerden konnte.\n" );
			}
		}
		if(last == "none"){
			result_last = NASLString( "Fehler" );
			if(result_last != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /usr/bin/last nicht gefunden\nwerden konnte.\n" );
			}
		}
		if(tmpfiles == "none"){
			result_tmpfiles = NASLString( "Fehler" );
			if(result_tmpfiles != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Dateien /var/log/?tmp* nicht gefunden\nwerden konnten.\n" );
			}
		}
	}
	if(ps != "none"){
		if( IsMatchRegexp( ps, "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*" ) ){
			result_ps = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Datei /bin/ps\nfolgende korrekte Sicherheiteinstellungen\nfestgestellt: " + ps + "\n\n" );
		}
		else {
			result_ps = NASLString( "fail" );
			if( IsMatchRegexp( ps, "-(rwx)(r|-)(w|-)(x|-).*" ) ) {
				secval = "-rwxr-x---";
			}
			else {
				if(IsMatchRegexp( ps, "-(r-x)(r|-)(w|-)(x|-).*" )){
					secval = "-r-xr-x---";
				}
			}
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Datei\n/bin/ps folgende fehlerhafte Sicherheitseinstellungen\nfestgestellt: " + ps + "\nBitte ändern Sie diese auf " + secval + " \n\n" );
		}
	}
	if(finger != "none"){
		if( IsMatchRegexp( finger, "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*" ) ){
			result_finger = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Datei\n/usr/bin/finger folgende korrekte Sicherheitsein-\nstellungen festgestellt: " + finger + "\n\n" );
		}
		else {
			result_finger = NASLString( "fail" );
			if( IsMatchRegexp( finger, "-(rwx)(r|-)(w|-)(x|-).*" ) ) {
				secval = "-rwxr-x---";
			}
			else {
				if(IsMatchRegexp( finger, "-(r-x)(r|-)(w|-)(x|-).*" )){
					secval = "-r-xr-x---";
				}
			}
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Datei\n/usr/bin/finger folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: " + finger + "\nBitte ändern Sie diese auf " + secval + " \n\n" );
		}
	}
	if(who != "none"){
		if( IsMatchRegexp( who, "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*" ) ){
			result_who = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Datei\n/usr/bin/who folgende korrekte Sicherheitsein-\nstellungen festgestellt: " + who + "\n\n" );
		}
		else {
			result_who = NASLString( "fail" );
			if( IsMatchRegexp( who, "-(rwx)(r|-)(w|-)(x|-).*" ) ) {
				secval = "-rwxr-x---";
			}
			else {
				if(IsMatchRegexp( who, "-(r-x)(r|-)(w|-)(x|-).*" )){
					secval = "-r-xr-x---";
				}
			}
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Datei\n/usr/bin/who folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: " + who + "\nBitte ändern Sie diese auf " + secval + " \n\n" );
		}
	}
	if(last != "none"){
		if( IsMatchRegexp( last, "-(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)---.*" ) ){
			result_last = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Datei\n/usr/bin/last folgende korrekte Sicherheitsein-\nstellungen festgestellt: " + last + "\n\n" );
		}
		else {
			result_last = NASLString( "fail" );
			if( IsMatchRegexp( last, "-(rwx)(r|-)(w|-)(x|-).*" ) ) {
				secval = "-rwxr-x---";
			}
			else {
				if(IsMatchRegexp( last, "-(r-x)(r|-)(w|-)(x|-).*" )){
					secval = "-r-xr-x---";
				}
			}
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Datei\n/usr/bin/last folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: " + last + "\nBitte ändern Sie diese auf " + secval + " \n\n" );
		}
	}
	if(tmpfiles != "none"){
		Lst = split( buffer: tmpfiles, keep: 0 );
		for(i = 0;i < max_index( Lst );i++){
			if(!IsMatchRegexp( Lst[i], "-rw-(r|-)(w|-)----.*" )){
				faillist += Lst[i] + "\n";
			}
		}
		if( !faillist ){
			result_tmpfiles = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Dateien\n/var/log/?tmp* folgende korrekte Sicherheitsein-\nstellungen festgestellt: " + tmpfiles + "\n\n" );
		}
		else {
			result_tmpfiles = NASLString( "fail" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Dateien\n/var/log/?tmp* folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: " + faillist + "\nBitte ändern Sie diese auf -rw-rw----.\n\n" );
		}
	}
	if( !result && ( result_ps == "fail" || result_finger == "fail" || result_who == "fail" || result_last == "fail" || result_tmpfiles == "fail" ) ) {
		result = NASLString( "nicht erfüllt" );
	}
	else {
		if( !result && ( result_ps == "Fehler" || result_finger == "Fehler" || result_who == "Fehler" || result_last == "Fehler" || result_tmpfiles == "Fehler" ) ) {
			result = NASLString( "Fehler" );
		}
		else {
			if(!result && result_ps == "ok" && result_finger == "ok" && result_who == "ok" && result_last == "ok" && result_tmpfiles == "ok"){
				result = NASLString( "erfüllt" );
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_022/result", value: result );
set_kb_item( name: "GSHB/M4_022/desc", value: desc );
set_kb_item( name: "GSHB/M4_022/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_022" );
}
exit( 0 );

