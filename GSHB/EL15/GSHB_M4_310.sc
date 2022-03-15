if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94231" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.310: Einrichtung des LDAP-Zugriffs auf Verzeichnisdienste" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04310.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.310: Einrichtung des LDAP-Zugriffs auf Verzeichnisdienste.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.310: Einrichtung des LDAP-Zugriffs auf Verzeichnisdienste\n";
gshbm = "IT-Grundschutz M4.310: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSTYPE = get_kb_item( "WMI/WMI_OSTYPE" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
log = get_kb_item( "WMI/WMI_OS/log" );
PORT389 = get_kb_list( "Ports/tcp/389" );
PORT636 = get_kb_list( "Ports/tcp/636" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( ContainsString( OSVER, "none" ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( OSVER == "5.1" || ( OSVER == "5.2" && ContainsString( "Microsoft(R) Windows(R) XP Professional x64 Edition", OSNAME ) ) || ( OSVER == "6.0" && OSTYPE == 1 ) || ( OSVER == "6.1" && OSTYPE == 1 ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System ist kein Server." );
		}
		else {
			if( PORT389 ){
				if( PORT636 ){
					result = NASLString( "erfüllt" );
					desc = NASLString( "LDAP über SSL/TLS ist aktiviert." );
				}
				else {
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "LDAP über SSL/TLS ist nicht aktiviert." );
				}
			}
			else {
				if( PORT636 ){
					result = NASLString( "erfüllt" );
					desc = NASLString( "LDAP ist nur über SSL/TLS aktiviert." );
				}
				else {
					result = NASLString( "nicht zutreffen" );
					desc = NASLString( "LDAP ist auf dem Server nicht installiert." );
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_310/result", value: result );
set_kb_item( name: "GSHB/M4_310/desc", value: desc );
set_kb_item( name: "GSHB/M4_310/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_310" );
}
exit( 0 );

