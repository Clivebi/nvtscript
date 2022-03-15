if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94194" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien" );
	script_add_preference( name: "Alle Dateien Auflisten", type: "checkbox", value: "no" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_PathVariables.sc", "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_SSH_executable_path.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.023: Sicherer Aufruf ausführbarer Dateien\n";
gshbm = "IT-Grundschutz M4.023: ";
require("ssh_func.inc.sc");
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSWINDIR = get_kb_item( "WMI/WMI_OSWINDIR" );
WINPATH = get_kb_item( "WMI/WinPathVar" );
if(WINPATH){
	WINPATHFOR = split( buffer: WINPATH, sep: ";", keep: 0 );
}
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
executable = get_kb_item( "GSHB/executable" );
writeexecutable = get_kb_item( "GSHB/write-executable" );
path = get_kb_item( "GSHB/path" );
exlog = get_kb_item( "GSHB/executable/log" );
log = get_kb_item( "WMI/WinPathVar/log" );
verbose = script_get_preference( "Alle Dateien Auflisten" );
if( !ContainsString( "none", OSVER ) ){
	if( !OSVER || isnull( WINPATHFOR ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		for(p = 0;p < max_index( WINPATHFOR );p++){
			if( !ContainsString( WINPATHFOR[p], OSWINDIR ) ) {
				PATH = "FALSE";
			}
			else {
				PATH = "TRUE";
			}
			PATHCHECK = PATHCHECK + PATH;
		}
		WINPATH = ereg_replace( string: WINPATH, pattern: ";", replace: ";\\n" );
		if( ContainsString( PATHCHECK, "FALSE" ) ){
			result = NASLString( "nicht erfüllt" );
			desc = NASLString( "Das System enthält folgende PATH-Variable:\n" + WINPATH + "\nBitte prüfen Sie auch die Benutzervariablen, da nur\ndie Systemvariable für PATH geprüft werden konnte." );
		}
		else {
			result = NASLString( "erfüllt" );
			desc = NASLString( "Das System enthält folgende PATH-Variable:\n" + WINPATH + "\nBitte prüfen Sie auch die Benutzervariablen, da nur\ndie Systemvariable für PATH geprüft werden konnte." );
		}
	}
}
else {
	if( !IsMatchRegexp( executable, "(I|i)nvalid switch" ) && !IsMatchRegexp( writeexecutable, "(I|i)nvalid switch" ) ){
		path = split( buffer: path, sep: "\"", keep: 0 );
		path = split( buffer: path[1], sep: ":", keep: 0 );
		for(i = 0;i < max_index( path );i++){
			if(!ContainsString( "./", path[i] )){
				continue;
			}
			Lst1 += path[i] + ":";
		}
		if( !Lst1 ) {
			path = "none";
		}
		else {
			path = Lst1;
		}
		if( ContainsString( "error", executable ) ){
			result = NASLString( "Fehler" );
			if(!exlog){
				desc = NASLString( "Beim Testen des Systems trat ein unbekannter\nFehler auf." );
			}
			if( exlog && log ) {
				desc = NASLString( "Beim Testen des Systems traten folgende Fehler auf:\n" + log + "\n" + exlog );
			}
			else {
				if(exlog && !log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + exlog );
				}
			}
		}
		else {
			if( !ContainsString( "none", path ) || !ContainsString( "none", executable ) || !ContainsString( "none", writeexecutable ) ){
				result = NASLString( "nicht erfüllt" );
				if(!ContainsString( "none", path )){
					desc = NASLString( "Folgende PATH-Variable sollte entfernt werden:\n" + path + "\n\n" );
				}
				if(!ContainsString( "none", writeexecutable )){
					desc += NASLString( "\nFolgende Dateien sind für Benutzer ausführbar und\nbeschreibbar:\n" + writeexecutable + "\n\n" );
				}
				if( verbose == "yes" ){
					if(!ContainsString( "none", executable )){
						desc += NASLString( "Folgende, außerhalb von /usr/local/bin/:/usr/bin/:\n/bin/:/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:\n/var/lib/:/lib/:/usr/lib/:/etc/, liegende\nDateien sind für Benutzer ausführbar und sollten\nentfernt bzw. die Rechte geändert werden:\n" + executable + "\n\n" );
					}
				}
				else {
					if(!ContainsString( "none", executable )){
						desc += NASLString( "Außerhalb von /usr/local/bin/:/usr/bin/:/bin/:\n/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:\n/var/lib/:/lib/:/usr/lib/:/etc/, wurden\nDateien gefunden, die für Benutzer ausführbar sind.\nSie sollten entfernt, bzw. es sollten die Rechte\ngeändert werden.\nFür eine vollständige Liste wählen\nSie bei den Voreinstellungen dieses Tests: Alle\nDateien Auflisten\n" );
					}
				}
			}
			else {
				result = NASLString( "erfüllt" );
				desc = NASLString( "Das System genügt den Anforderungen\\nder Maßnahme 4.023.\\n" );
			}
		}
	}
	else {
		if( IsMatchRegexp( path, "/cygdrive/./(W|w)indows" ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			result = NASLString( "Fehler" );
			if(!exlog){
				desc = NASLString( "Beim Testen des Systems trat ein unbekannter\nFehler auf." );
			}
			if(exlog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + exlog );
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_023/result", value: result );
set_kb_item( name: "GSHB/M4_023/desc", value: desc );
set_kb_item( name: "GSHB/M4_023/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_023" );
}
exit( 0 );

