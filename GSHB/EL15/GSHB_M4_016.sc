if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94183" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.016: Zugangsbeschränkungen für Benutzer-Kennungen und oder Terminals" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04016.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_timerestriction.sc", "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_LDAP_User_w_LogonHours.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.016: Zugangsbeschränkungen für Benutzer-Kennungen und oder Terminals.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.016: Zugangsbeschränkungen für Benutzer-Kennungen und oder Terminals\n";
gshbm = "IT-Grundschutz M4.016: ";
LogonHours = get_kb_item( "GSHB/LDAP_LogonHours" );
log = get_kb_item( "GSHB/LDAP_LogonHours/log" );
timerest = get_kb_item( "GSHB/timerest" );
timerestlog = get_kb_item( "GSHB/timerest/log" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
WindowsDomainrole = get_kb_item( "WMI/WMI_WindowsDomainrole" );
if( ( ContainsString( "error", LogonHours ) && WindowsDomainrole == "none" ) && ContainsString( "error", timerest ) ){
	result = NASLString( "Fehler" );
	if(!log && !timerestlog){
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
	}
	if(log || timerestlog){
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" );
		if(log){
			desc += NASLString( "Windows WMI Fehler: " + log );
		}
		if(timerestlog){
			desc += NASLString( "\nSSH Fehler: " + timerestlog );
		}
	}
}
else {
	if( !ContainsString( "none", OSNAME ) ){
		if(LogonHours != "none" && LogonHours != "error"){
			LogonHours_split = split( buffer: LogonHours, sep: "\n", keep: 0 );
			for(i = 0;i < max_index( LogonHours_split );i++){
				LogonUsers = split( buffer: LogonHours_split[i], sep: "|", keep: 0 );
				User += LogonUsers[0] + "; ";
			}
		}
		if( ContainsString( "error", LogonHours ) && ( WindowsDomainrole == 4 || WindowsDomainrole == 5 || WindowsDomainrole == "none" ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( ContainsString( "error", LogonHours ) && ( WindowsDomainrole == "none" || WindowsDomainrole < 4 ) ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Das System ist kein Windows Domaincontroller. Die\\nKonfiguration der Domainuser kann nur an\\nDomaincontrollern getestet werden." );
			}
			else {
				if( LogonHours == "none" ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Es wurden keine Benutzer gefunden, die eine\nBeschränkung in Ihrer Loginzeit haben!" );
				}
				else {
					if(User){
						result = NASLString( "unvollständig" );
						desc = NASLString( "Es wurden Benutzer gefunden, die eine Beschränkung in\nIhrer Loginzeit haben.\nBitte prüfen Sie, ob alle\nBenutzer aufgeführt sind:\n" + User );
					}
				}
			}
		}
	}
	else {
		if( timerest == "windows" ){
			result = NASLString( "Fehler" );
			if( !ContainsString( "none", OSNAME ) && !ContainsString( "error", OSNAME ) ) {
				desc = NASLString( "Folgendes System wurde erkannt:\n" + OSNAME + "\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n" + WMIOSLOG );
			}
			else {
				desc = NASLString( "Das System scheint ein Windows-System zu sein.\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n" + WMIOSLOG );
			}
		}
		else {
			if( ContainsString( "error", timerest ) ){
				result = NASLString( "Fehler" );
				if(!timerestlog){
					desc = NASLString( "Beim Testen des Systems trat ein\nunbekannter Fehler auf." );
				}
				if(timerestlog){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + timerestlog );
				}
			}
			else {
				if( ContainsString( "notfound", timerest ) ){
					result = NASLString( "unvollständig" );
					desc = NASLString( "Die Datei /etc/security/time.conf wurde nicht gefunden\n. Bitte prüfen Sie ob die Beschränkung der Loginzeiten\nauf eine andere Art konfiguriert ist." );
				}
				else {
					if( ContainsString( "none", timerest ) ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Es konnten keine Einträge in /etc/security/time.conf\ngefunden werden." );
					}
					else {
						if(!ContainsString( "none", timerest )){
							result = NASLString( "erfüllt" );
							desc = NASLString( "Folgende Einträge wurden in /etc/security/time.conf\ngefunden:\n" + timerest + "\nBitte prüfen Sie, ob die Einträge vollständig sind!" );
						}
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_016/result", value: result );
set_kb_item( name: "GSHB/M4_016/desc", value: desc );
set_kb_item( name: "GSHB/M4_016/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_016" );
}
exit( 0 );

