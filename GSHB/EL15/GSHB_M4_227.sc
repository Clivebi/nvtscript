if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94219" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.227: Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04227.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_NtpServer.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/NtpServer", "WMI/WMI_WindowsDomain" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.227: Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.227: Einsatz eines lokalen NTP-Servers zur Zeitsynchronisation\n";
gshbm = "IT-Grundschutz M4.227: ";
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
ntpserver = get_kb_item( "WMI/NtpServer" );
ntpserver = tolower( ntpserver );
domain = get_kb_item( "WMI/WMI_WindowsDomain" );
domain = tolower( domain );
log = get_kb_item( "WMI/NtpServer/log" );
if(!ContainsString( "none", ntpserver ) && !ContainsString( "error", ntpserver )){
	ntpserver = split( buffer: ntpserver, sep: ",", keep: 0 );
}
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( ContainsString( ntpserver, "error" ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( ntpserver, "none" ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Auf dem System wurde kein Eintrag für einen\\nNTP-Server gefunden" );
		}
		else {
			if( ContainsString( ntpserver[0], domain ) ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Auf dem System wurde ein lokaler NTP-Server\\nhinterlegt: " + ntpserver[0] );
			}
			else {
				if(!ContainsString( ntpserver[0], domain )){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Auf dem System wurde ein externer NTP-Server\\nhinterlegt: " + ntpserver[0] );
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_227/result", value: result );
set_kb_item( name: "GSHB/M4_227/desc", value: desc );
set_kb_item( name: "GSHB/M4_227/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_227" );
}
exit( 0 );

