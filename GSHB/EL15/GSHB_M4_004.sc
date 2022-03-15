if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94175" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken für Wechselmedien und externen Datenspeichern" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_WMI_removable-media.sc", "GSHB/GSHB_SSH_USB_storage.sc" );
	script_require_keys( "WMI/CD_driver_start", "WMI/FD_driver_start", "WMI/SF_driver_start", "WMI/USB_driver_start", "WMI/StorageDevicePolicies" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken für Wechselmedien und externen Datenspeicher.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.004: Geeigneter Umgang mit Laufwerken für Wechselmedien und externen Datenspeichern\n";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
cdstart = get_kb_item( "WMI/CD_driver_start" );
fdstart = get_kb_item( "WMI/FD_driver_start" );
sfstart = get_kb_item( "WMI/SF_driver_start" );
usbstart = get_kb_item( "WMI/USB_driver_start" );
sdp = get_kb_item( "WMI/StorageDevicePolicies" );
log = get_kb_item( "WMI/StorageDevicePolicies/log" );
usbmodules = get_kb_item( "GSHB/usbmodules" );
usbstorage = get_kb_item( "GSHB/usbstorage" );
usbbus = get_kb_item( "GSHB/usbbus" );
sshlog = get_kb_item( "GSHB/usbmodules/log" );
gshbm = "IT-Grundschutz M4.004: ";
if( !ContainsString( "none", OSNAME ) || ContainsString( usbbus, "windows" ) ){
	if( ContainsString( "error", cdstart ) && ContainsString( "error", fdstart ) && ContainsString( "error", sfstart ) && ContainsString( "error", usbstart ) && ContainsString( "error", sdp ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( "inapplicable", cdstart ) && ContainsString( "inapplicable", fdstart ) && ContainsString( "inapplicable", sfstart ) && ContainsString( "inapplicable", usbstart ) && ContainsString( "inapplicable", sdp ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System wurde nicht getestet, da es anscheinend\\nkein Windows-System ist." );
		}
		else {
			if( ContainsString( "off", cdstart ) && ContainsString( "off", fdstart ) && ContainsString( "off", sfstart ) && ContainsString( "off", usbstart ) ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Dienste für Wechseldatenträger sind deaktiviert." );
			}
			else {
				if( ContainsString( "off", cdstart ) && ContainsString( "off", fdstart ) && ContainsString( "off", sfstart ) && ContainsString( "inapplicable", usbstart ) ){
					result = NASLString( "erfüllt" );
					desc = NASLString( "Dienste für Wechseldatenträger sind deaktiviert.\\nAllerdings wurde noch kein USB-Gerät angeschlossen,\\nso dass dort kein Test durchgeführt werden konnte." );
				}
				else {
					if( ( ContainsString( "on", cdstart ) || ContainsString( "on", fdstart ) || ContainsString( "on", sfstart ) || ContainsString( "on", usbstart ) ) && ContainsString( "on", sdp ) ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Dienste für Wechseldatenträger sind nicht deaktiviert.\\nAllerdings wurden sie auf 'nur lesen' gesetzt." );
					}
					else {
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Dienste für Wechseldatenträger sind nicht deaktiviert." );
					}
				}
			}
		}
	}
}
else {
	if(ContainsString( "none", OSNAME ) || !ContainsString( usbbus, "windows" )){
		if( ContainsString( "error", usbmodules ) && ContainsString( "error", usbstorage ) && ContainsString( "error", usbbus ) ){
			result = NASLString( "Fehler" );
			if(!sshlog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(sshlog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + sshlog );
			}
		}
		else {
			if( ContainsString( "none", usbmodules ) && ContainsString( "none", usbstorage ) && ContainsString( "none", usbbus ) ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Es konnte kein angeschlossenes USB-Storage Gerät\\ngefunden werden. Des weiteren wurde keine USB-Storage\\nKernelmodule gefunden." );
			}
			else {
				result = NASLString( "nicht erfüllt" );
				if(usbstorage != "none"){
					desc = NASLString( "Es wurden folgende angeschlossenen USB-Storage Gerät\ngefunden:\n" + usbstorage + "\n" );
				}
				if(usbmodules != "none"){
					desc += NASLString( "Es wurden folgende USB-Storage Kernelmodule gefunden:\n" + usbmodules + "\n" );
				}
				if(usbbus != "none"){
					desc += NASLString( "Aufgrund der vorgefundenen Verzeichnisstrucktur\n-/sys/bus/usb/drivers/usb-storage- muss davon aus-\ngegangen werden, dass USB-Storage Kernelmodule\nvorhanden sind:\n" + usbbus + "\n" );
				}
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_004/result", value: result );
set_kb_item( name: "GSHB/M4_004/desc", value: desc );
set_kb_item( name: "GSHB/M4_004/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_004" );
}
exit( 0 );

