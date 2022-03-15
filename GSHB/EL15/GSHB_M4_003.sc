if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94174" );
	script_version( "$Revision: 10396 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.003: Einsatz von Viren-Schutzprogrammen" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "GSHB/GSHB_WMI_Antivir.sc", "gather-package-list.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.003: Einsatz von Viren-Schutzprogrammen.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04003.html" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("itg.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M4.003: Einsatz von Viren-Schutzprogrammen\n";
gshbm = "IT-Grundschutz M4.003: ";
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item( "ssh/login/uname" );
if( SAMBA || ( SSHUNAME && ( !ContainsString( SSHUNAME, "command not found" ) && !ContainsString( SSHUNAME, "CYGWIN" ) ) ) ){
	rpms = get_kb_item( "ssh/login/packages" );
	if( rpms ){
		pkg1 = "clamav";
		pkg2 = "clamav-freshclam";
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
		if( rpms = get_kb_item( "ssh/login/rpms" ) ){
			tmp = split( buffer: rpms, keep: 0 );
			if(max_index( tmp ) <= 1){
				tmp = split( buffer: rpms, sep: ";", keep: 0 );
				rpms = "";
				for(i = 0;i < max_index( tmp );i++){
					rpms += tmp[i] + "\n";
				}
			}
			pkg1 = "clamav";
			pkg2 = "clamav-freshclam";
			pkg3 = "clamav-update";
			pat1 = NASLString( "(", pkg1, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
			pat2 = NASLString( "(", pkg2, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
			pat3 = NASLString( "(", pkg3, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
			desc1 = eregmatch( pattern: pat1, string: rpms );
			desc2 = eregmatch( pattern: pat2, string: rpms );
			desc3 = eregmatch( pattern: pat3, string: rpms );
			if(desc1){
				name1 = desc1[1];
				version1 = desc1[2];
			}
			if( desc2 ){
				name2 = desc2[1];
				version2 = desc2[2];
			}
			else {
				if(desc3){
					name2 = desc3[1];
					version2 = desc3[2];
				}
			}
		}
		else {
			rpms = get_kb_item( "ssh/login/solpackages" );
			pkg1 = "clamav";
			pat1 = NASLString( "([a-zA-Z0-9]+)[ ]{1,}(.*", pkg1, ".*)[ ]{1,}([a-zA-Z0-9/\\._ \\(\\),-:\\+\\{\\}\\&]+)" );
			desc1 = eregmatch( pattern: pat1, string: rpms );
			if(desc1){
				name1 = desc1[3];
			}
		}
	}
	if( !SSHUNAME ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Ein Login über SSH war nicht erfolgreich." );
	}
	else {
		if( !rpms ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Vom System konnte keine Paketliste mit installierter\\nSoftware geladen werden." );
		}
		else {
			if( IsMatchRegexp( SSHUNAME, "SunOS.*" ) ){
				if( !desc1 ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Die Antivirensoftware ClamAV konnte nicht auf dem\\nSystem gefunden werden." );
				}
				else {
					if(desc1){
						result = NASLString( "erfüllt" );
						desc = NASLString( "Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden. Folgende Version ist installiert:\n" + name1 );
					}
				}
			}
			else {
				if( !desc1 && ( !desc2 || !desc3 ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Die Antivirensoftware ClamAV konnte nicht auf dem\\nSystem gefunden werden." );
				}
				else {
					if( desc1 && ( !desc2 && !desc3 ) ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Die Antivirensoftware ClamAV konnte auf dem System\\ngefunden werden, allerdings wurde Freshclam/ClamAV-\\nupdate nicht installiert." );
					}
					else {
						if( desc1 && ( desc2 || desc3 ) ){
							result = NASLString( "erfüllt" );
							desc = NASLString( "Die Antivirensoftware ClamAV konnte auf dem System\ngefunden werden. Folgende Version ist installiert:\n" + name1 + "  " + version1 + "\n" + name2 + "  " + version2 );
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
	if( !SAMBA && ( !SSHUNAME || ContainsString( SSHUNAME, "command not found" ) || ContainsString( SSHUNAME, "CYGWIN" ) ) ){
		log = get_kb_item( "WMI/Antivir/log" );
		Antivir = get_kb_item( "WMI/Antivir" );
		if(!Antivir){
			Antivir = "None";
		}
		AntivirName = get_kb_item( "WMI/Antivir/Name" );
		AntivirUptoDate = get_kb_item( "WMI/Antivir/UptoDate" );
		if(!ContainsString( "None", AntivirUptoDate )){
			AntivirUptoDate = split( buffer: AntivirUptoDate, sep: "|", keep: 0 );
		}
		AntivirEnable = get_kb_item( "WMI/Antivir/Enable" );
		if(!ContainsString( "None", AntivirEnable )){
			AntivirEnable = split( buffer: AntivirEnable, sep: "|", keep: 0 );
		}
		AntivirState = get_kb_item( "WMI/Antivir/State" );
		if(!ContainsString( "None", AntivirState )){
			AntivirState = split( buffer: AntivirState, sep: "|", keep: 0 );
		}
		if( ContainsString( "error", Antivir ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( ContainsString( "Server", Antivir ) ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Das System ist ein Windows Server. Solche Systeme \\nkönnen leider nicht getestet werden" );
			}
			else {
				if( ContainsString( "None", Antivir ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Auf dem System wurde kein Antivierenprogramm gefunden" );
				}
				else {
					if( ContainsString( "Windows XP <= SP1", Antivir ) ){
						result = NASLString( "nicht zutreffend" );
						desc = NASLString( "Das System ist ein Windows XP System kleiner oder\\ngleich Service Pack 1 und kann nicht getestet werden" );
					}
					else {
						if( !ContainsString( "None", AntivirName ) && ContainsString( "None", AntivirState ) ){
							if( ContainsString( AntivirEnable[2], "True" ) && ContainsString( AntivirUptoDate[2], "True" ) ){
								result = NASLString( "erfüllt" );
								desc = NASLString( "Das System hat einen Virenscanner installiert,\\nwelcher läuft und aktuell ist." );
							}
							else {
								if( ContainsString( AntivirEnable[2], "True" ) && ContainsString( AntivirUptoDate[2], "False" ) ){
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Das System hat einen Virenscanner istalliert,\\nwelcher läuft aber veraltet ist." );
								}
								else {
									if( ContainsString( AntivirEnable[2], "False" ) && ContainsString( AntivirUptoDate[2], "True" ) ){
										result = NASLString( "nicht erfüllt" );
										desc = NASLString( "Das System hat einen Virenscanner installiert,\\nwelcher aus aber aktuell ist." );
									}
									else {
										if(ContainsString( AntivirEnable[2], "False" ) && ContainsString( AntivirUptoDate[2], "False" )){
											result = NASLString( "nicht erfüllt" );
											desc = NASLString( "Das System hat einen Virenscanner installiert,\\nwelcher aus und veraltet ist." );
										}
									}
								}
							}
						}
						else {
							if( !ContainsString( "None", AntivirName ) && !ContainsString( "None", AntivirState ) ){
								if( ContainsString( AntivirState[2], "266240" ) ){
									result = NASLString( "erfüllt" );
									desc = NASLString( "Das System hat einen Virenscanner installiert,\\nwelcher läuft und aktuell ist." );
								}
								else {
									if( ContainsString( AntivirState[2], "266256" ) ){
										result = NASLString( "nicht erfüllt" );
										desc = NASLString( "Das System hat einen Virenscanner installiert,\\nwelcher läuft aber veraltet ist." );
									}
									else {
										if( ContainsString( AntivirState[2], "262144" ) || ContainsString( AntivirState[2], "270336" ) ){
											result = NASLString( "nicht erfüllt" );
											desc = NASLString( "Das System hat einen Virenscanner installiert,\\nwelcher aus aber aktuell ist." );
										}
										else {
											if(ContainsString( AntivirState[2], "262160" ) || ContainsString( AntivirState[2], "270352" )){
												result = NASLString( "nicht erfüllt" );
												desc = NASLString( "Das System hat einen Virenscanner installiert,\\nwelcher aus und veraltet ist." );
											}
										}
									}
								}
							}
							else {
								result = NASLString( "Fehler" );
								desc = NASLString( "Beim Testen des Systems trat ein unbekannter\\nFehler auf." );
							}
						}
					}
				}
			}
		}
	}
	else {
		result = NASLString( "Fehler" );
		desc = NASLString( "Beim Testen des Systems trat ein unbekannter\\nFehler auf." );
	}
}
set_kb_item( name: "GSHB/M4_003/result", value: result );
set_kb_item( name: "GSHB/M4_003/desc", value: desc );
set_kb_item( name: "GSHB/M4_003/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_003" );
}
exit( 0 );

