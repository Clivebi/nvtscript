if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94205" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs für ein Windows-System" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04049.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_BootDrive.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/FS", "WMI/FDD", "WMI/CD", "WMI/USB", "WMI/BOOTINI" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs für ein Windows-System.

Stand: 15. Ergänzungslieferung (15. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.049: Absicherung des Boot-Vorgangs für ein Windows-System\n";
gshbm = "IT-Grundschutz M4.049: ";
FS = get_kb_item( "WMI/FS" );
FDD = get_kb_item( "WMI/FDD" );
CD = get_kb_item( "WMI/CD" );
USB = get_kb_item( "WMI/USB" );
BOOTINI = get_kb_item( "WMI/BOOTINI" );
log = get_kb_item( "WMI/BOOTDRIVE/log" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba, es ist kein\\nMicrosoft Windows System." );
}
else {
	if( ContainsString( FS, "error" ) || ContainsString( FDD, "error" ) || ContainsString( CD, "error" ) || ContainsString( USB, "error" ) || ContainsString( BOOTINI, "error" ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( FS, "None" ) && ContainsString( FDD, "None" ) && ContainsString( CD, "None" ) && ContainsString( USB, "None" ) || ContainsString( BOOTINI, "none" ) ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		else {
			if( ContainsString( BOOTINI, "True" ) || !ContainsString( FDD, "None" ) || !ContainsString( CD, "None" ) || !ContainsString( USB, "None" ) || ContainsString( FS, "FAT" ) ){
				result = NASLString( "nicht erfüllt" );
				if(ContainsString( BOOTINI, "True" )){
					desc = NASLString( "Boot.ini ist beschreibbar, bitte achten Sie darauf,\\ndass die Boot.ini schreibgeschützt ist und ent-\\nsprechende NTFS Berechtigungen gesetzt sind." + "\n" );
				}
				if(!ContainsString( FDD, "None" )){
					desc = desc + NASLString( "Sie sollten aus Sicherheitsgründen das Diskettenlauf-\\nwerk entfernen oder zumindest sperren." + "\n" );
				}
				if(!ContainsString( CD, "None" )){
					desc = desc + NASLString( "Sie sollten aus Sicherheitsgründen das CD-ROM Laufwerk\\nentfernen oder zumindest sperren." + "\n" );
				}
				if(!ContainsString( USB, "None" )){
					desc = desc + NASLString( "Sie sollten aus Sicherheitsgründen den USB Controller\\nentfernen oder zumindest im BIOS deaktivieren." + "\n" );
				}
				if(ContainsString( FS, "FAT" )){
					LD = split( buffer: FS, sep: "\n", keep: 0 );
					for(i = 1;i < max_index( LD );i++){
						LDinf = split( buffer: LD[i], sep: "|", keep: 0 );
						if(LDinf != NULL){
							if(ContainsString( LDinf[1], "FAT" )){
								LDdesc = LDdesc + "Laufwerksbuchstabe: " + LDinf[0] + ", Dateisystem: " + LDinf[1] + ", ";
							}
						}
					}
					desc = desc + NASLString( "Folgende Logischen Laufwerke sind nicht\\nNFTS-formatiert: " + "\n" + LDdesc + "\n" );
				}
				desc += "Prüfen Sie zudem, ob bei UEFI-basierten Geräten UEFI Secure Boot aktiviert ist.\n";
			}
			else {
				if(!ContainsString( FS, "FAT" ) && ContainsString( FDD, "None" ) && ContainsString( CD, "None" ) && ContainsString( USB, "None" ) && ContainsString( BOOTINI, "False" )){
					result = NASLString( "erfüllt" );
					desc = NASLString( "Ihr System entspricht der Maßnahme M4.049.\\nPrüfen Sie zudem, ob bei UEFI-basierten Geräten UEFI Secure Boot aktiviert ist." );
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_049/result", value: result );
set_kb_item( name: "GSHB/M4_049/desc", value: desc );
set_kb_item( name: "GSHB/M4_049/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_049" );
}
exit( 0 );

