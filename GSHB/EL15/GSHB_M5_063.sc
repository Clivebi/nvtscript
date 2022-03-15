if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95062" );
	script_version( "$Revision: 10396 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M5.063: Einsatz von GnuPG oder PGP" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "gather-package-list.sc", "GSHB/GSHB_WMI_GnuPGandPGP.sc", "GSHB/GSHB_SSH_pubring.sc", "GSHB/GSHB_WMI_OSInfo.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_require_keys( "WMI/GnuPGVersion" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05063.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.063: Einsatz von GnuPG oder PGP.

  Stand: 14. Erg‰nzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("itg.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M5.063: Einsatz von GnuPG oder PGP\n";
GnuPGVersion = get_kb_item( "WMI/GnuPGVersion" );
PGPVersion = get_kb_item( "WMI/PGPVersion" );
GnuPGpubringsUser = get_kb_item( "WMI/GnuPGpubringsUser" );
PGPpubringsUser = get_kb_item( "WMI/PGPpubringsUser" );
OSVER = get_kb_item( "SMB/WindowsVersion" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
wmilog = get_kb_item( "WMI/PGP/log" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
gshbm = "GSHB Maﬂnahme 5.063: ";
pubrings = get_kb_item( "GSHB/pubrings" );
log = get_kb_item( "GSHB/pubrings/log" );
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item( "ssh/login/uname" );
if( SAMBA || ( SSHUNAME && !ContainsString( SSHUNAME, "command not found" ) && !ContainsString( SSHUNAME, "CYGWIN" ) ) ){
	rpms = get_kb_item( "ssh/login/packages" );
	if( rpms ){
		pkg1 = "gnupg";
		pkg2 = "gnupg2";
		pat1 = NASLString( "ii  (", pkg1, ") +([0-9]:)?([^ ]+)" );
		pat2 = NASLString( "ii  (", pkg2, ") +([0-9]:)?([^ ]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
		name1 = desc1[1];
		version1 = desc1[3];
		name2 = desc2[1];
		version2 = desc2[3];
	}
	else {
		rpms = get_kb_item( "ssh/login/rpms" );
		tmp = split( buffer: rpms, keep: 0 );
		if(max_index( tmp ) <= 1){
			tmp = split( buffer: rpms, sep: ";", keep: 0 );
			rpms = "";
			for(i = 0;i < max_index( tmp );i++){
				rpms += tmp[i] + "\n";
			}
		}
		pkg1 = "gnupg";
		pkg2 = "gnupg2";
		pat1 = NASLString( "(", pkg1, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
		pat2 = NASLString( "(", pkg2, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
		if(desc1){
			name1 = desc1[1];
			version1 = desc1[2];
		}
		if(desc2){
			name2 = desc2[1];
			version2 = desc2[2];
		}
	}
	if( pubrings == "windows" ){
		result = NASLString( "Fehler" );
		if( !ContainsString( "none", OSNAME ) && !ContainsString( "error", OSNAME ) ) {
			desc = NASLString( "Folgendes System wurde erkannt:\n" + OSNAME + "\nAllerdings konnte auf das System nicht korrekt zugegriffen\nwerden. Folgende Fehler sind aufgetreten:\n" + wmilog );
		}
		else {
			desc = NASLString( "Das System scheint ein Windows-System zu sein. Allerdings\nkonnte auf das System nicht korrekt zugegriffen werden.\nFolgende Fehler sind aufgetreten:\n" + wmilog );
		}
	}
	else {
		if( ContainsString( "error", pubrings ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( !SSHUNAME ){
				result = NASLString( "Fehler" );
				desc = NASLString( "Ein Login ¸ber SSH war nicht erfolgreich." );
			}
			else {
				if( !rpms ){
					result = NASLString( "Fehler" );
					desc = NASLString( "Vom System konnte keine Paketliste mit installierter\\nSoftware geladen werden." );
				}
				else {
					if( !desc1 && !desc2 ){
						result = NASLString( "nicht zutreffend" );
						desc = NASLString( "Auf dem System wurde keine GnuPG-Standardinstallation gefunden." );
					}
					else {
						if( desc1 || desc2 ){
							result = NASLString( "erf¸llt" );
							if( desc1 && !desc2 ) {
								desc = NASLString( "Folgende GnuPG-Version ist installiert:\n" + name1 + "  " + version1 + "\nPr¸fen Sie, ob dies die aktuellste Version ist!\n" );
							}
							else {
								if( desc2 && !desc1 ) {
									desc = NASLString( "Folgende GnuPG-Version ist installiert:\n" + name2 + "  " + version2 + "\nPr¸fen Sie, ob dies die aktuellste Version ist!\n" );
								}
								else {
									if(desc1 && desc2){
										desc = NASLString( "Folgende GnuPG-Version ist installiert:\n" + name1 + "  " + version1 + "\n" + name2 + "  " + version2 + "\nPr¸fen Sie, ob dies die aktuellste Version ist!\n" );
									}
								}
							}
							if(pubrings != "none"){
								desc = desc + NASLString( "Folgende Benutzer setzen GnuPG ein:\n" + pubrings + "\n" );
							}
						}
						else {
							result = NASLString( "Fehler" );
							desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf." );
						}
					}
				}
			}
		}
	}
}
else {
	if( ContainsString( "error", GnuPGVersion ) ){
		result = NASLString( "Fehler" );
		if(!wmilog){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(wmilog){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + wmilog );
		}
	}
	else {
		if( ContainsString( "none", GnuPGVersion ) && ContainsString( "none", PGPVersion ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Auf dem System wurde keine GnuPG- bzw. PGP-Standardinstallation\\ngefunden." );
		}
		else {
			result = NASLString( "erf¸llt" );
			if(GnuPGVersion != "none"){
				desc = NASLString( "Folgende GnuPG-Version ist installiert: " + GnuPGVersion + "\nPr¸fen Sie, ob dies die aktuellste Version ist!\n" );
			}
			if(GnuPGpubringsUser != "none"){
				desc = desc + NASLString( "Folgende Benutzer setzen GnuPG ein:\n" + GnuPGpubringsUser + "\n" );
			}
			if(PGPVersion != "none"){
				desc = desc + NASLString( "Folgende PGP-Version ist installiert: " + PGPVersion + "\nPr¸fen Sie, ob dies die aktuellste Version ist!\n" );
			}
			if(PGPpubringsUser != "none"){
				PGPpubringsUser = ereg_replace( string: PGPpubringsUser, pattern: " ;", replace: ";\\n" );
				desc = desc + NASLString( "Folgende Benutzer setzen PGP ein:\n" + PGPpubringsUser + "\n" );
			}
		}
	}
}
set_kb_item( name: "GSHB/M5_063/result", value: result );
set_kb_item( name: "GSHB/M5_063/desc", value: desc );
set_kb_item( name: "GSHB/M5_063/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_063" );
}
exit( 0 );

