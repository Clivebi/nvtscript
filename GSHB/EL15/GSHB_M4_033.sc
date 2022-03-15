if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94199" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datenträgeraustausch und Datenübertragung" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04033.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_Antivir.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/Antivir" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datenträgeraustausch und Datenübertragung.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.033: Einsatz eines Viren-Suchprogramms bei Datenträgeraustausch und Datenübertragung\n";
gshbm = "IT-Grundschutz M4.033: ";
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
Antivir = get_kb_item( "WMI/Antivir" );
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
log = get_kb_item( "WMI/Antivir/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba, dieser Test läuft nur auf\\nMicrosoft Windows Systemen." );
}
else {
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
			desc = NASLString( "Das System ist ein Server und kann nicht\\ngetestet werden." );
		}
		else {
			if( ContainsString( "None", Antivir ) ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Auf dem System wurde kein Antivirenprogramm gefunden." );
			}
			else {
				if( ContainsString( "Server", Antivir ) ){
					result = NASLString( "nicht zutreffend" );
					desc = NASLString( "Das System ist ein Server und kann nicht\\ngetestet werden." );
				}
				else {
					if( ContainsString( "Windows XP <= SP1", Antivir ) ){
						result = NASLString( "nicht zutreffend" );
						desc = NASLString( "Das System ist ein Windows XP System kleiner oder\\ngleich Service Pack 1 und kann nicht getestet werden." );
					}
					else {
						if( !ContainsString( "None", AntivirName ) && ContainsString( "None", AntivirState ) ){
							if( ContainsString( AntivirEnable[2], "True" ) && ContainsString( AntivirUptoDate[2], "True" ) ){
								result = NASLString( "erfüllt" );
								desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nläuft und aktuell ist." );
							}
							else {
								if( ContainsString( AntivirEnable[2], "True" ) && ContainsString( AntivirUptoDate[2], "False" ) ){
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nläuft aber veraltet ist." );
								}
								else {
									if( ContainsString( AntivirEnable[2], "False" ) && ContainsString( AntivirUptoDate[2], "True" ) ){
										result = NASLString( "nicht erfüllt" );
										desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nausgeschaltet aber aktuell ist." );
									}
									else {
										if(ContainsString( AntivirEnable[2], "False" ) && ContainsString( AntivirUptoDate[2], "False" )){
											result = NASLString( "nicht erfüllt" );
											desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nausgeschaltet und veraltet ist." );
										}
									}
								}
							}
						}
						else {
							if(!ContainsString( "None", AntivirName ) && !ContainsString( "None", AntivirState )){
								if( ContainsString( AntivirState[2], "266240" ) ){
									result = NASLString( "erfüllt" );
									desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nläuft und aktuell ist." );
								}
								else {
									if( ContainsString( AntivirState[2], "266256" ) ){
										result = NASLString( "nicht erfüllt" );
										desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nläuft aber veraltet ist." );
									}
									else {
										if( ContainsString( AntivirState[2], "262144" ) || ContainsString( AntivirState[2], "270336" ) ){
											result = NASLString( "nicht erfüllt" );
											desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nausgeschaltet aber aktuell ist." );
										}
										else {
											if(ContainsString( AntivirState[2], "262160" ) || ContainsString( AntivirState[2], "270352" )){
												result = NASLString( "nicht erfüllt" );
												desc = NASLString( "Das System hat einen Virenscanner installiert, welcher\\nausgeschaltet und veraltet ist." );
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_033/result", value: result );
set_kb_item( name: "GSHB/M4_033/desc", value: desc );
set_kb_item( name: "GSHB/M4_033/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_033" );
}
exit( 0 );

