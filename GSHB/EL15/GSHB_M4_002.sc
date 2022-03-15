if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94173" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.002: Bildschirmsperre" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_ScreenSaver_Status.sc", "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_SSH_gnome_kde_screensaver.sc" );
	script_require_keys( "WMI/Screensaver" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.002: Bildschirmsperre.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Windows: Kann nur für Lokale Konten getestet werden.

  Linux: Nur voreingestellte Bildschirmschoner bei Gnome und KDE." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.002: Bildschirmsperre\n";
gshbm = "IT-Grundschutz M4.002: ";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
Screensaver = get_kb_item( "WMI/Screensaver" );
log = get_kb_item( "WMI/Screensaver/log" );
Domainrole = get_kb_item( "WMI/WMI_WindowsDomainrole" );
gnomescreensaver = get_kb_item( "GSHB/gnomescreensaver" );
screensaverdaemon = get_kb_item( "GSHB/screensaverdaemon" );
defkdescreensav = get_kb_item( "GSHB/defkdescreensav" );
userkdescreensav = get_kb_item( "GSHB/userkdescreensav" );
sshlog = get_kb_item( "GSHB/gnomescreensaver/log" );
if( !ContainsString( "none", OSNAME ) ){
	if( ContainsString( "error", Screensaver ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( "none", Screensaver ) && Domainrole != 1 ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf, es konnten keine\\nEinstellungen in der Registry gefunden werden." );
		}
		else {
			if( ContainsString( "none", Screensaver ) && Domainrole == 1 ){
				result = NASLString( "Fehler" );
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf, es konnten keine\\nEinstellungen in der Registry gefunden werden. Das liegt daran,\\ndass das System Domainmitglied ist. Domainuser können nicht\\ngetestet werden." );
			}
			else {
				Lst = split( buffer: Screensaver, sep: "\n", keep: 0 );
				for(i = 0;i < max_index( Lst );i++){
					screenresult = split( buffer: Lst[i], sep: ";", keep: 0 );
					if( ( screenresult[1] == "ScreenSaveActive=1" && screenresult[2] == "ScreenSaverIsSecure=1" ) || ( screenresult[4] == "DomScreenSaveActive=1" && screenresult[5] == "DomScreenSaverIsSecure=1" ) ){
						testval += 0;
					}
					else {
						testval += 1;
						faultusers += screenresult[0] + ";";
					}
				}
				if( Domainrole == 1 ){
					if( testval <= 0 ){
						result = NASLString( "unvollständig" );
						desc = NASLString( "Es wurde für alle lokalen Benutzer die Bildschirmsperre mit\nPasswortschutz aktiviert. Achtung, Domainuser können nicht\ngetestet werden." );
					}
					else {
						if(testval > 0){
							result = NASLString( "nicht erfüllt" );
							desc = NASLString( "Für folgende lokalen Benutzer ist die Bildschirmsperre mit\nPasswortschutz nicht aktiviert:\n" + faultusers + "\nAchtung, Domainuser können nicht getestet werden." );
						}
					}
				}
				else {
					if( testval <= 0 ){
						result = NASLString( "erfüllt" );
						desc = NASLString( "Es wurde für alle Benutzer die Bildschirmsperre mit\\nPasswortschutz aktiviert." );
					}
					else {
						if(testval > 0){
							result = NASLString( "nicht erfüllt" );
							desc = NASLString( "Für folgende Benutzer ist die Bildschirmsperre mit\nPasswortschutz nicht aktiviert:\n" + faultusers );
						}
					}
				}
			}
		}
	}
}
else {
	if( gnomescreensaver != "none" && gnomescreensaver != "windows" ){
		if( ContainsString( "error", gnomescreensaver ) ){
			result = NASLString( "Fehler" );
			if(!sshlog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf, siehe Log Message." );
			}
			if(sshlog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + sshlog );
			}
		}
		else {
			if( gnomescreensaver == "true" && screensaverdaemon != "false" ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Es wurde die Bildschirmsperre mit Passwortschutz aktiviert." );
				if(screensaverdaemon == "none"){
					desc += NASLString( "\nDer Schlüsselname\n/apps/gnome_settings_daemon/screensaver/start_screensaver\nwurde nicht gefunden." );
				}
			}
			else {
				if( gnomescreensaver == "true" && screensaverdaemon == "false" ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Es wurde die Bildschirmsperre mit Passwortschutz aktiviert.\nAllerdings steht der Schlüsselname\n/apps/gnome_settings_daemon/screensaver/start_screensaver\nauf false. Setzen Sie diesen Wert auf »True«, um den\nBildschirmschoner beim Anmelden zu starten." );
				}
				else {
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Es wurde keine Bildschirmsperre mit Passwortschutz aktiviert." );
				}
			}
		}
	}
	else {
		if( defkdescreensav != "none" && defkdescreensav != "windows" ){
			if( ContainsString( "error", defkdescreensav ) ){
				result = NASLString( "Fehler" );
				if(!sshlog){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf, siehe Log Message." );
				}
				if(sshlog){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + sshlog );
				}
			}
			else {
				if( defkdescreensav == "true" && userkdescreensav == "true" ){
					result = NASLString( "erfüllt" );
					desc = NASLString( "Es wurde die Bildschirmsperre mit Passwortschutz aktiviert." );
				}
				else {
					if( defkdescreensav == "false" && userkdescreensav == "true" ){
						result = NASLString( "unvollständig" );
						desc = NASLString( "Es wurde die Bildschirmsperre mit Passwortschutz bei allen\nUsern aktiviert.\nAllerdings wurde die Bildschirmsperre mit\nPasswortschutz in der Datei\n/etc/kde4/share/config/kscreensaverrc nicht richtig\nkonfiguriert." );
					}
					else {
						if(defkdescreensav == "true" && userkdescreensav == "false"){
							result = NASLString( "nicht erfüllt" );
							desc = NASLString( "Es gibt User bei denen die Bildschirmsperre mit Passwortschutz\\nnicht aktiviert ist." );
						}
					}
				}
			}
		}
		else {
			if( ContainsString( "windows", defkdescreensav ) || ContainsString( "windows", gnomescreensaver ) ){
				result = NASLString( "Fehler" );
				if( !ContainsString( "none", OSNAME ) && !ContainsString( "error", OSNAME ) ) {
					desc = NASLString( "Folgendes System wurde erkannt:\n" + OSNAME + "\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n" + log );
				}
				else {
					desc = NASLString( "Das System scheint ein Windows-System zu sein. Allerdings\nkonnte auf das System nicht korrekt zugegriffen werden.\nFolgende Fehler sind aufgetreten:\n" + log );
				}
			}
			else {
				result = NASLString( "Fehler" );
				desc = NASLString( "Es wurde versucht, die Konfiguration der Bildschirmsperre mit\nPasswortschutz, auf dem System zu erkennen. Dabei wurde auf\nWindows, GNOME und KDE Standardeinstellungen getestet. Keines\nder Systeme konnte dabei aufgrund von Standardeinstellungen\nerkannt werden." );
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf bzw.\nes konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_002/result", value: result );
set_kb_item( name: "GSHB/M4_002/desc", value: desc );
set_kb_item( name: "GSHB/M4_002/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_002" );
}
exit( 0 );

