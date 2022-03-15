if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95069" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M5.090: Einsatz von IPSec unter Windows" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05090.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_IPSec_Policy.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/IPSecPolicy" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.090: Einsatz von IPSec unter Windows.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.090: Einsatz von IPSec unter Windows\n";
IPSecPolicy = get_kb_item( "WMI/IPSecPolicy" );
log = get_kb_item( "WMI/IPSecPolicy/log" );
NoDefaultExempt = get_kb_item( "WMI/NoDefaultExempt" );
SMBOSVER = get_kb_item( "SMB/WindowsVersion" );
OSVER = get_kb_item( "WMI/WMI_OSVER" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
gshbm = "GSHB Maßnahme 5.090: ";
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( ContainsString( "error", IPSecPolicy ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( OSVER >= 6 ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System wurde nicht getestet, da es kein Windows 2000\\noder XP System ist." );
		}
		else {
			if( ContainsString( "off", IPSecPolicy ) ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Es wurde keine IPSec Policy hinterlegt" );
			}
			else {
				if( NoDefaultExempt == 1 ){
					result = NASLString( "erfüllt" );
					desc = NASLString( "Folgende IPSec Policy wurde hinterlegt:\\n" + IPSecPolicy );
				}
				else {
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Folgende IPSec Policy wurde hinterlegt:\\n" + IPSecPolicy + "\nFür -HKLM\\SYSTEM\\CurrentControlSet\\Services\\IPSEC-,\nREG_DWORD: -NoDefaultExempt- wurde nicht wie im Grundschutz-\nKatalog gefordert der Wert -1- hinterlegt." );
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M5_090/result", value: result );
set_kb_item( name: "GSHB/M5_090/desc", value: desc );
set_kb_item( name: "GSHB/M5_090/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_090" );
}
exit( 0 );

