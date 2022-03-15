if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95061" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M5.059: Schutz vor DNS-Spoofing bei Authentisierungsmechanismen" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05059.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_nsswitch.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.059: Schutz vor DNS-Spoofing bei Authentisierungsmechanismen.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.059: Schutz vor DNS-Spoofing bei Authentisierungsmechanismen\n";
gshbm = "IT-Grundschutz M5.059: ";
nsswitch = get_kb_item( "GSHB/nsswitch/hosts" );
hosts = get_kb_item( "GSHB/dns/hosts" );
log = get_kb_item( "GSHB/dns/log" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( nsswitch == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( ContainsString( "error", nsswitch ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
		else {
			if( ContainsString( "none", nsswitch ) ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Auf dem System wurde keine Hosts-Konfiguration in\n/etc/nsswitch.conf gefunden." );
			}
			else {
				if( !ContainsString( "none", nsswitch ) && !ContainsString( "nogrep", nsswitch ) && !IsMatchRegexp( nsswitch, "hosts:[ \t]+files.*" ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Auf dem System wurde in der Hosts-Konfiguration in\n/etc/nsswitch.conf, kein -files- Eintrag gefunden bzw. er steht\nnicht wie gefordert an erster Stelle:\n\n" + nsswitch );
				}
				else {
					if( !ContainsString( "none", nsswitch ) && !ContainsString( "nogrep", nsswitch ) ){
						result = NASLString( "erfüllt" );
						desc = NASLString( "Bitte prüfen Sie, ob die Ergebnisse den Anforderungen der\nMaßnahme 5.059 entsprechen! Auf dem System konnte folgende\nHosts-Konfiguration in /etc/nsswitch.conf gefunden werden:\n\n" + nsswitch + "\nFolgende Einstellungen wurden in /etc/hosts gefunden:\n\n" + hosts );
					}
					else {
						if(ContainsString( "nogrep", nsswitch ) || ContainsString( "nogrep", hosts )){
							result = NASLString( "Fehler" );
							desc += NASLString( "Beim Testen des Systems wurde der Befehl grep nicht gefunden." );
						}
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M5_059/result", value: result );
set_kb_item( name: "GSHB/M5_059/desc", value: desc );
set_kb_item( name: "GSHB/M5_059/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_059" );
}
exit( 0 );

