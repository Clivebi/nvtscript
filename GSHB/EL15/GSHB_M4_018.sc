if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94185" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.018: Administrative und technische Absicherung des Zugangs zum Monitor- und Single-User-Modus" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04018.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_singleuser_login.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.018: Administrative und technische Absicherung des Zugangs zum Monitor- und Single-User-Modus.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.018: Administrative und technische Absicherung des Zugangs zum Monitor- und Single-User-Modus\n";
gshbm = "IT-Grundschutz M4.018: ";
inittab = get_kb_item( "GSHB/inittab" );
inittabS = get_kb_item( "GSHB/inittabS" );
inittab1 = get_kb_item( "GSHB/inittab1" );
rcSconf = get_kb_item( "GSHB/rcSconf" );
rcSsulogin = get_kb_item( "GSHB/rcSsulogin" );
log = get_kb_item( "GSHB/inittab/log" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( inittab == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( ContainsString( "error", inittab ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein\nunbekannter Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
		else {
			if( ContainsString( "none", inittab ) && ContainsString( "none", rcSconf ) && ContainsString( "none", rcSsulogin ) ){
				result = NASLString( "Fehler" );
				desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass die\nDateie etc/inittab, /etc/init/rcS.conf und\n/etc/event.d/rcS-sulogin nicht gefunden werden konnte." );
			}
			else {
				if( ContainsString( "nocat", inittab ) || ContainsString( "nocat", rcSconf ) || ContainsString( "nocat", rcSsulogin ) ){
					result = NASLString( "Fehler" );
					desc = NASLString( "Beim Testen des Systems wurde der Befehl\ncat nicht gefunden." );
				}
				else {
					if( inittab != "none" && inittab == "noperm" ){
						result = NASLString( "Fehler" );
						desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass Sie\nkeine Berechtigung haben die Datei /etc/inittab\nzu lesen." );
					}
					else {
						if(inittab != "none" && inittab != "noperm" && inittabS != "none" && inittab1 != "none"){
							if( ContainsString( inittabS, "sulogin" ) ){
								result = NASLString( "erfüllt" );
								desc = NASLString( "Folgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/inittab gefunden:\n" + inittabS );
							}
							else {
								if( ContainsString( inittab1, "sulogin" ) ){
									result = NASLString( "erfüllt" );
									desc = NASLString( "Folgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/inittab gefunden:\n" + inittab1 );
								}
								else {
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Folgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/inittab gefunden:\n" + inittabS + "\nFolgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/inittab gefunden:\n" + inittab1 );
								}
							}
						}
					}
					if( rcSconf != "none" && rcSconf == "noperm" ){
						result = NASLString( "Fehler" );
						desc += NASLString( "Beim Testen des Systems wurde festgestellt, das Sie\nkeine Berechtigung haben die Datei /etc/init/rcS.conf\nzu lesen." );
					}
					else {
						if(rcSconf != "none" && rcSconf != "noperm"){
							if( IsMatchRegexp( rcSconf, "right:.*" ) ){
								rcSconf = split( buffer: rcSconf, sep: ":", keep: 0 );
								result = NASLString( "erfüllt" );
								desc = NASLString( "Folgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/init/rcS.conf gefunden:\n" + rcSconf[1] );
							}
							else {
								if( IsMatchRegexp( rcSconf, "wrong:.*" ) ){
									rcSconf = split( buffer: rcSconf, sep: ":", keep: 0 );
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Folgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/init/rcS.conf gefunden:\n" + rcSconf[1] );
								}
								else {
									if(IsMatchRegexp( rcSconf, "unknown:.*" )){
										rcSconf = split( buffer: rcSconf, sep: ":", keep: 0 );
										result = NASLString( "nicht erfüllt" );
										desc = NASLString( "Es konnte nicht korrekt ermittel werden, ob eine Shell\noder sulogin genutzt wird. Folgender Eintrag wurde für\nden Single-User-Modus in der Datei /etc/init/rcS.conf\ngefunden:\n" + rcSconf[1] + ":" + rcSconf[2] );
									}
								}
							}
						}
					}
					if( rcSsulogin != "none" && rcSsulogin == "noperm" ){
						result = NASLString( "Fehler" );
						desc += NASLString( "Beim Testen des Systems wurde festgestellt, das Sie\nkeine Berechtigung haben die Datei\n/etc/event.d/rcS-sulogin zu lesen." );
					}
					else {
						if(rcSsulogin != "none" && rcSsulogin != "noperm"){
							if( IsMatchRegexp( rcSsulogin, "right:.*" ) ){
								rcSsulogin = split( buffer: rcSsulogin, sep: ":", keep: 0 );
								result = NASLString( "erfüllt" );
								desc = NASLString( "Folgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/event.d/rcS-sulogin gefunden:\n" + rcSsulogin[1] );
							}
							else {
								if( IsMatchRegexp( rcSsulogin, "wrong:.*" ) ){
									rcSsulogin = split( buffer: rcSsulogin, sep: ":", keep: 0 );
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Folgender Eintrag wurde für den Single-User-Modus in\nder Datei /etc/event.d/rcS-sulogin gefunden:\n" + rcSsulogin[1] );
								}
								else {
									if(IsMatchRegexp( rcSsulogin, "unknown:.*" )){
										rcSsulogin = split( buffer: rcSsulogin, sep: ":", keep: 0 );
										result = NASLString( "nicht erfüllt" );
										desc = NASLString( "Es konnte nicht korrekt ermittel werden, ob eine Shell\noder sulogin genutzt wird.\nFolgender Eintrag wurde\nfür den Single-User-Modus in der Datei\n/etc/event.d/rcS-sulogin gefunden:\n" + rcSsulogin[1] + ":" + rcSsulogin[2] );
									}
								}
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
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_018/result", value: result );
set_kb_item( name: "GSHB/M4_018/desc", value: desc );
set_kb_item( name: "GSHB/M4_018/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_018" );
}
exit( 0 );

