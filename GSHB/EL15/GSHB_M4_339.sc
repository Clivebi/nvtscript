if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94243" );
	script_version( "$Revision: 12387 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.339: Verhindern unautorisierter Nutzung von Wechselmedien unter Windows-Clients ab Windows Vista" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04339.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_WMI_CD-Autostart.sc", "GSHB/GSHB_WMI_Driver-Autostart.sc", "GSHB/GSHB_WMI_CD-FD-User-only-access.sc", "GSHB/GSHB_WMI_AllowRemoteDASD.sc" );
	script_require_keys( "WMI/AllowRemoteDASD" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.339: Verhindern unautorisierter Nutzung von Wechselmedien unter Windows-Clients ab Windows Vista.

  Stand: 15. Ergänzungslieferung (15. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.339: Verhindern unautorisierter Nutzung von Wechselmedien unter Windows-Clients ab Windows Vista\n";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
cdauto = get_kb_item( "WMI/CD_Autostart" );
cdalloc = get_kb_item( "WMI/CD_Allocated" );
fdalloc = get_kb_item( "WMI/FD_Allocated" );
AllowRemoteDASD = get_kb_item( "WMI/AllowRemoteDASD" );
AllowRemoteDASD = get_kb_item( "WMI/AllowRemoteDASD/log" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
driverauto = get_kb_item( "WMI/Driver_Autoinstall" );
allowAdminInstall = get_kb_item( "WMI/AllowAdminInstall" );
gshbm = "GSHB Maßnahme 4.339: ";
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( AllowRemoteDASD == "error" ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( OSVER >= "6.0" && OSTYPE == "1" ){
			if( ContainsString( "on", cdauto ) || ContainsString( "off", cdalloc ) || ContainsString( "off", fdalloc ) || AllowRemoteDASD != "0" || driverauto != "off" || ContainsString( "on", allowAdminInstall ) ){
				result = NASLString( "nicht erfüllt" );
				if(ContainsString( "on", cdauto )){
					desc = NASLString( "CD-Autostart ist nicht deaktiviert!\n" );
				}
				if(ContainsString( "off", cdalloc )){
					desc += NASLString( "CD-Zugriff ist weiterhin über Netzwerk möglich!\n" );
				}
				if(ContainsString( "off", fdalloc )){
					desc += NASLString( "FD-Zugriff ist weiterhin über Netzwerk möglich!\n" );
				}
				if(AllowRemoteDASD != "0"){
					desc += NASLString( "Direkter Zugriff auf Wechselmedien in Remotesitzungen\nist weiterhin möglich.\n" );
				}
				if(driverauto != "off"){
					desc += NASLString( "Die automatische Installation von Treibern ist möglich.\n" );
				}
				if(ContainsString( "on", allowAdminInstall )){
					desc += NASLString( "Administratoren können keine Treiber unabhängig\nder Gruppenrichtlinie installieren oder aktualisieren.\n" );
				}
			}
			else {
				if(ContainsString( "off", cdauto ) && ContainsString( "on", cdalloc ) && ContainsString( "on", fdalloc ) && AllowRemoteDASD == "0" || driverauto == "off" || allowAdminInstall == "on"){
					result = NASLString( "erfüllt" );
					desc = NASLString( "Das System entspricht der IT-Grundschutz Maßnahme\\nM4.339." );
				}
			}
		}
		else {
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Microsoft Windows System größer gleich Windows Vista." );
		}
	}
}
set_kb_item( name: "GSHB/M4_339/result", value: result );
set_kb_item( name: "GSHB/M4_339/desc", value: desc );
set_kb_item( name: "GSHB/M4_339/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_339" );
}
exit( 0 );

