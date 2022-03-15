if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94218" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.200: Umgang mit USB-Speichermedien" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04200.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_removable-media.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/USB_driver_start", "WMI/CD_driver_start" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.200: Umgang mit USB-Speichermedien.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.200: Umgang mit USB-Speichermedien\n";
usbstart = get_kb_item( "WMI/USB_driver_start" );
cdstart = get_kb_item( "WMI/CD_driver_start" );
log = get_kb_item( "WMI/StorageDevicePolicies/log" );
gshbm = "GSHB Maßnahme 4.200: ";
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( ContainsString( "error", usbstart ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( "inapplicable", usbstart ) && ContainsString( "inapplicable", cdstart ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System wurde nicht getestet,\\nda es anscheinend kein Windows-System ist." );
		}
		else {
			if( ContainsString( "inapplicable", usbstart ) && ( ContainsString( "on", cdstart ) || ContainsString( "off", cdstart ) ) ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Es wurde anscheinend noch kein USB-Gerät ange-\\nschlossen, so dass dort kein Test durchgeführt\\nwerden konnte." );
			}
			else {
				if( ContainsString( "on", usbstart ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "USB-Treiberstart ist nicht deaktiviert." );
				}
				else {
					result = NASLString( "erfüllt" );
					desc = NASLString( "USB-Treiberstart ist deaktiviert." );
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_200/result", value: result );
set_kb_item( name: "GSHB/M4_200/desc", value: desc );
set_kb_item( name: "GSHB/M4_200/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_200" );
}
exit( 0 );

