if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95057" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_r-tools.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.020: Einsatz der Sicherheitsmechanismen von rlogin, rsh und rcp\n";
gshbm = "IT-Grundschutz M5.020: ";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
rhosts = get_kb_item( "GSHB/R-TOOL/rhosts" );
hostsequiv = get_kb_item( "GSHB/R-TOOL/hostsequiv" );
lshostsequiv = get_kb_item( "GSHB/R-TOOL/lshostsequiv" );
inetdconf = get_kb_item( "GSHB/R-TOOL/inetdconf" );
rlogind = get_kb_item( "GSHB/R-TOOL/rlogind" );
rshd = get_kb_item( "GSHB/R-TOOL/rshd" );
log = get_kb_item( "GSHB/R-TOOL/log" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( rhosts == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( rhosts == "error" ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( rhosts == "not found" && ( hostsequiv == "none" || hostsequiv == "noentry" ) && ( lshostsequiv == "none" || IsMatchRegexp( lshostsequiv, ".......---...root root.*" ) ) && ( inetdconf == "noentry" || inetdconf == "none" ) && rlogind == "not found" && rshd == "not found" ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Das System entspricht der Maßnahme 5.020." );
			}
			else {
				if(rhosts != "not found" || ( hostsequiv != "noentry" && hostsequiv != "none" ) || ( lshostsequiv != "none" && !IsMatchRegexp( lshostsequiv, ".......---...root root.*" ) )){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Es muss sichergestellt werden, dass die Dateien\n$HOME/.rhosts und /etc/hosts.equiv nicht vorhanden sind oder\ndass sie leer sind und der Benutzer keine Zugriffsrechte auf\nsie hat." );
					if(rhosts != "not found"){
						desc += NASLString( "\nFolgende .rhost Dateien wurden gefunden:\n" + rhosts );
					}
					if(hostsequiv != "none"){
						val = split( buffer: lshostsequiv, sep: " ", keep: 0 );
						desc += NASLString( "\nFolgende Zugriffsrechte gelten für -/etc/hosts.equiv- :\n" + val[0] + " " + val[2] + " " + val[3] );
					}
					if(hostsequiv != "noentry" && hostsequiv != "none"){
						desc += NASLString( "\nFolgende Einträge wurden in  -/etc/hosts.equiv- gefunden:\n" + hostsequiv );
					}
					if(ContainsString( hostsequiv, "+" )){
						desc += NASLString( "\nSollte die Benutzung der Datei -/etc/hosts.equiv- unumgänglich\nsein, muss sichergestellt sein, dass kein Eintrag + vorhanden\nist, da hierdurch jeder Rechner vertrauenswürdig würde." );
					}
					if(rlogind != "not found" || rshd != "not found"){
						desc += NASLString( "\nEs sollte verhindert werden, dass die Daemons rlogind und rshd\ngestartet werden können. (siehe hierzu die Datei\n/etc/inetd.conf und Maßnahme M 5.16)" );
						if( inetdconf != "none" && inetdconf != "noentry" ) {
							desc += NASLString( "\nFolgende Einträge stehen in Ihrer -/etc/inetd.conf-:\n" + inetdconf );
						}
						else {
							desc += NASLString( "\nIhre -/etc/inetd.conf- ist leer." );
						}
					}
				}
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M5_020/result", value: result );
set_kb_item( name: "GSHB/M5_020/desc", value: desc );
set_kb_item( name: "GSHB/M5_020/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_020" );
}
exit( 0 );

