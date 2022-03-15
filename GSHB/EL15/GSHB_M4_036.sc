if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94201" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_name( "IT-Grundschutz M4.036: Sperren bestimmter Faxempfänger-Rufnummerne" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04036.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "toolcheck.sc", "GSHB/GSHB_TELNET_Cisco_Voice.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.036: Sperren bestimmter Faxempfänger-Rufnummerne.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Cisco Geräte können nur über Telnet getestet werden, da sie SSH blowfish-cbc encryption nicht unterstützen." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.036: Sperren bestimmter Faxempfänger-Rufnummerne\n";
gshbm = "IT-Grundschutz M4.036: ";
ciscovoice = get_kb_item( "GSHB/Voice" );
log = get_kb_item( "GSHB/Voice/log" );
translation = get_kb_item( "GSHB/Voice/translation" );
if( log == "no Telnet Port" ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Beim Testen des Systems wurde kein Telnet-\nPort gefunden." );
}
else {
	if( ciscovoice == "no credentials set" ){
		result = NASLString( "unvollständig" );
		desc = NASLString( "Um diesen Test durchzuführen, muss ihn in den Vorein-\nstellungen unter:-IT-Grundschutz: List reject Rule on\nCisco Voip Devices over Telnet- ein Benutzername und\nPasswort eingetragen werden." );
	}
	else {
		if( ciscovoice == "Login Failed" ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Es war nicht möglich sich am Zielsystem anzumelden." );
		}
		else {
			if( ciscovoice == "nocisco" ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Das Ziel konnt nicht als Cisco-Gerät erkannt werden." );
			}
			else {
				if( ciscovoice == "novoice" ){
					result = NASLString( "nicht zutreffend" );
					desc = NASLString( "Das Ziel konnt als Cisco-Gerät erkannt werden.\nAllerdings konnte keine Voice-Funktion erkannt werden." );
				}
				else {
					if( translation == "noconfig" ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Auf dem Cisco-Gerät wurde Voip Funktionalitäten\nentdeckt. Allerdings konnte keine -translation-rule-\nnacht dem Muster - rule .* reject .*- entdeckt werden." );
					}
					else {
						if(translation != "noconfig"){
							result = NASLString( "unvollständig" );
							desc = NASLString( "Auf dem Cisco-Gerät wurde Voip Funktionalitäten ent-\ndeckt. Es wurden folgende -translation-rule- gefunden:\n" + translation + "\nBitte Prüfen Sie ob alle ggf. zu sperrenden Fax-\nempfänger-Rufnummern eingetragen sind." );
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
set_kb_item( name: "GSHB/M4_036/result", value: result );
set_kb_item( name: "GSHB/M4_036/desc", value: desc );
set_kb_item( name: "GSHB/M4_036/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_036" );
}
exit( 0 );

