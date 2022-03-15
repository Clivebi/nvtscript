if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94203" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04040.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_SSH_audio.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Nur für Linux umgesetzt. Es ist unter Windows nicht möglich den Status des Mikrofons über Registry/WMI auszulesen." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras\n";
gshbm = "IT-Grundschutz M4.040: ";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
package = get_kb_item( "GSHB/AUDIO/package" );
devaudio = get_kb_item( "GSHB/AUDIO/devaudio" );
log = get_kb_item( "GSHB/AUDIO/log" );
syslog = get_kb_item( "GSHB/syslog" );
rsyslog = get_kb_item( "GSHB/rsyslog" );
log_rsyslog = get_kb_item( "GSHB/rsyslog/log" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "unvollständig" );
	desc = NASLString( "Es ist unter Windows nicht möglich, den Status des\nMikrofons über Registry/WMI auszulesen." );
}
else {
	if( devaudio != "windows" ){
		if( ContainsString( devaudio, "error" ) ){
			result = NASLString( "Fehler" );
			if(!log_rsyslog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log_rsyslog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( devaudio == "no audio" ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "In Ihrem System konnte keine Audio-Komponenten\nermittelt werden um ein Microfone anzuschließen." );
			}
			else {
				if( IsMatchRegexp( devaudio, ".......---.*root.audio.*" ) && package == "none" ){
					result = NASLString( "erfüllt" );
					desc = NASLString( "Der zugriff auf /dev/audio ist auf root beschränkt und\nes wurde keine der folgenden Audio-Server Pakete\ngefunden: esound, paudio, pulseaudio, artsd, phonon" );
				}
				else {
					if(!IsMatchRegexp( devaudio, ".......---.*root.audio.*" ) || package != "none"){
						result = NASLString( "nicht erfüllt" );
						if(!IsMatchRegexp( devaudio, ".......---.*root.audio.*" )){
							desc = NASLString( "Sie sollten den Zugriff auf /dev/audio\nauf root beschränken. " );
						}
						if(package != "none"){
							desc += NASLString( "Folgende Audioserver Pakete wurden auf dem\nSystem gefunden:\n" + package );
						}
					}
				}
			}
		}
	}
	else {
		result = NASLString( "Fehler" );
		desc = NASLString( "Beim Testen des Systems konnte dies nicht korrekt\nerkannt werden.\nSollte es sich um ein Windows-System\nhandeln, ist es nicht möglich den Status des Mikrofons\nüber Registry/WMI auszulesen." );
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_040/result", value: result );
set_kb_item( name: "GSHB/M4_040/desc", value: desc );
set_kb_item( name: "GSHB/M4_040/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_040" );
}
exit( 0 );

