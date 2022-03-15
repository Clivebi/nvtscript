if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94177" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "IT-Grundschutz M4.007: Änderung voreingestellter Passwörter" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04007.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_TELNET_BruteForce.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.007: Änderung voreingestellter Passwörter.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Test wird nur über SSH und Telnet ausgeführt." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.007: Änderung voreingestellter Passwörter\n";
gshbm = "IT-Grundschutz M4.007: ";
ssh = get_kb_item( "GSHB/BRUTEFORCE/SSH" );
telnet = get_kb_item( "GSHB/BRUTEFORCE/TELNET" );
if( ssh == "deactivated" ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Der Test wurde nicht aktiviert. Um diesen Test auszu-\nführen, müssen Sie ihn in den Voreinstellungen unter:\n-SSH and Telnet BruteForce attack- aktivieren." );
}
else {
	if( ssh == "nossh" && telnet == "notelnet" ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Das System kann nicht getestet werden, da weder per\nSSH noch per Telnet zugegriffen werden kann." );
	}
	else {
		if( ( ssh == "ok" && telnet == "ok" ) || ( ssh == "ok" && telnet == "notelnet" ) || ( ssh == "nossh" && telnet == "ok" ) ){
			result = NASLString( "erfüllt" );
			desc = NASLString( "Weder über SSH noch über Telnet konnte man sich mit\neinem Default-User und -Passwort anmelden." );
		}
		else {
			result = NASLString( "nicht erfüllt" );
			desc = NASLString( "Mit folgenden Daten konnte man sich am Ziel anmelden:\n" );
			if(ssh != "nossh" && ssh != "ok"){
				desc += NASLString( "SSH: " + ssh + "\n" );
			}
			if(telnet != "notelnet" && telnet != "ok"){
				desc += NASLString( "Telnet: " + telnet );
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_007/result", value: result );
set_kb_item( name: "GSHB/M4_007/desc", value: desc );
set_kb_item( name: "GSHB/M4_007/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_007" );
}
exit( 0 );

