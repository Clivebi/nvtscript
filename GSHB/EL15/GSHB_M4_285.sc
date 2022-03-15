if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94225" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.285: Deinstallation nicht benötigter Client-Funktionen von Windows Server 2003" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04285.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_W2K3_ClientFunk.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/Win2k3ClientFunktion/NetMeeting", "WMI/Win2k3ClientFunktion/OutlookExpress", "WMI/Win2k3ClientFunktion/Mediaplayer" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.285: Deinstallation nicht benötigter Client-Funktionen von Windows Server 2003.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.285: Deinstallation nicht benötigter Client-Funktionen von Windows Server 2003\n";
gshbm = "IT-Grundschutz M4.285: ";
ClFunk = get_kb_item( "WMI/Win2k3ClientFunktion" );
ClFunkNM = get_kb_item( "WMI/Win2k3ClientFunktion/NetMeeting" );
ClFunkOE = get_kb_item( "WMI/Win2k3ClientFunktion/OutlookExpress" );
ClFunkM = get_kb_item( "WMI/Win2k3ClientFunktion/Mediaplayer" );
log = get_kb_item( "WMI/Win2k3ClientFunktion/log" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba, es ist kein Microsoft System." );
}
else {
	if( ContainsString( ClFunk, "error" ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( ClFunk, "inapplicable" ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Windows 2003 Server." );
		}
		else {
			if( ContainsString( ClFunkNM, "none" ) && ContainsString( ClFunkOE, "none" ) && ContainsString( ClFunkM, "none" ) ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Auf dem System wurden die Client-Funktionen gemäß Maßnahme\nM4.284 entfernt. Beachten Sie bitte auch das ggf. noch lokale\noder Domain-Sicherheitsrichtlinien gesetzt werden sollten." );
			}
			else {
				if(!ContainsString( ClFunkNM, "none" ) || !ContainsString( ClFunkOE, "none" ) || !ContainsString( ClFunkM, "none" )){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Folgende Client-Funktionen befinden sich noch auf dem System:\n" + ClFunkNM + "\n" + ClFunkOE + "\n" + ClFunkM + "\n" + "Sie sollten die Programme zusätlich auch noch löschen/entfernen." );
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_285/result", value: result );
set_kb_item( name: "GSHB/M4_285/desc", value: desc );
set_kb_item( name: "GSHB/M4_285/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_285" );
}
exit( 0 );

