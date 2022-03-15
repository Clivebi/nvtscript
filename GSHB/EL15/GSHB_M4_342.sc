if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94247" );
	script_version( "$Revision: 12233 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-06 16:01:14 +0100 (Tue, 06 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.342: Aktivierung des Last Access Zeitstempels ab Windows Vista" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04342.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "Policy/Microsoft/WindowsGeneral/win_last_access_timestamp.sc" );
	script_require_keys( "1.3.6.1.4.1.25623.1.0.96047/RESULT" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.342: Aktivierung des Last Access Zeitstempels ab Windows Vista.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.342: Aktivierung des Last Access Zeitstempels ab Windows Vista\n";
gshbm = "IT-Grundschutz M4.342: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
NtfsDisableLastAccessUpdate = get_kb_item( "1.3.6.1.4.1.25623.1.0.96047/RESULT" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( NtfsDisableLastAccessUpdate == "-1" ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf. Der Registry-Wert konnte nicht gefunden werden." );
	}
	else {
		if( OSVER >= "6.0" && OSTYPE == "1" ){
			if( NtfsDisableLastAccessUpdate == "0" ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Das System Entspricht der IT-Grundschutz Maßnahme M4.342" );
			}
			else {
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Der Registry Wert für NtfsDisableLastAccessUpdate ist\nnicht wie gefordert -0-!" );
			}
		}
		else {
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Microsoft Windows System größer gleich Windows Vista." );
		}
	}
}
set_kb_item( name: "GSHB/M4_342/result", value: result );
set_kb_item( name: "GSHB/M4_342/desc", value: desc );
set_kb_item( name: "GSHB/M4_342/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_342" );
}
exit( 0 );

