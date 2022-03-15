if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94187" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "IT-Grundschutz M4.019: Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04019.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_umask.sc", "GSHB/GSHB_SSH_setuid.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.019: Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.019: Restriktive Attributvergabe bei Unix-Systemdateien und -verzeichnissen\n";
gshbm = "IT-Grundschutz M4.019: ";
umask = get_kb_item( "GSHB/umask" );
umasklog = get_kb_item( "GSHB/umask/log" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
setuid = get_kb_item( "GSHB/setuid/root" );
setuidlog = get_kb_item( "GSHB/setuid/log" );
tempsticky = get_kb_item( "GSHB/tempsticky" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Folgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( ContainsString( "error", umask ) ){
		result = NASLString( "Fehler" );
		if(!umasklog){
			desc = NASLString( "Beim Testen des Systems trat ein\nunbekannter Fehler auf." );
		}
		if(umasklog){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + umasklog );
		}
	}
	else {
		if( umask == "windows" ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System scheint ein Windows-System zu sein." );
		}
		else {
			if( ContainsString( "none", umask ) && ContainsString( "none", setuid ) && ( tempsticky == "true" || tempsticky == "notmp" ) ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Es konnten keine Fehlerhaften umask Einträge und\nDateien mit setuid-Bit unter /* gefunden werden." );
			}
			else {
				if(!ContainsString( "none", umask ) || !ContainsString( "none", setuid ) || tempsticky == "false"){
					result = NASLString( "nicht erfüllt" );
					if(!ContainsString( "none", umask )){
						desc = NASLString( "Folgende Fehlerhaften umask Einträge wurden gefunden:\n" + umask );
					}
					if(!ContainsString( "none", setuid )){
						desc += NASLString( "Folgende Dateien mit setuid-Bit wurden gefunden:\n" + setuid );
					}
					if(tempsticky == "false"){
						desc += NASLString( "Für das Verzeichnis /tmp wurde das sticky-Bit\nnicht gesetzt." );
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_019/result", value: result );
set_kb_item( name: "GSHB/M4_019/desc", value: desc );
set_kb_item( name: "GSHB/M4_019/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_019" );
}
exit( 0 );

