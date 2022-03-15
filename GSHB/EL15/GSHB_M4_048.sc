if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94204" );
	script_version( "$Revision: 12387 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.048: Passwortschutz unter Windows-Systemen" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04048.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_PasswdPolicie.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.048: Passwortschutz unter Windows-Systemen.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.048: Passwortschutz unter Windows-Systemen\n";
gshbm = "IT-Grundschutz M4.048: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
PP = get_kb_item( "WMI/passwdpolicy" );
LP = get_kb_item( "WMI/lockoutpolicy" );
PPS = get_kb_item( "WMI/lockoutpolicy/stat" );
LPS = get_kb_item( "WMI/passwdpolicy/stat" );
MINPA = get_kb_item( "WMI/passwdpolicy/MinimumPasswordAge" );
PHS = get_kb_item( "WMI/passwdpolicy/PasswordHistorySize" );
PHS = int( PHS );
LD = get_kb_item( "WMI/passwdpolicy/LockoutDuration" );
RLC = get_kb_item( "WMI/passwdpolicy/ResetLockoutCount" );
MPL = get_kb_item( "WMI/passwdpolicy/MinimumPasswordLength" );
LBC = get_kb_item( "WMI/passwdpolicy/LockoutBadCount" );
MAXPA = get_kb_item( "WMI/passwdpolicy/MaximumPasswordAge" );
RLTCP = get_kb_item( "WMI/lockoutpolicy/RequireLogonToChangePassword" );
PC = get_kb_item( "WMI/lockoutpolicy/PasswordComplexity" );
FLWHE = get_kb_item( "WMI/lockoutpolicy/ForceLogoffWhenHourExpire" );
CTP = get_kb_item( "WMI/lockoutpolicy/ClearTextPassword" );
PINLOGIN = get_kb_item( "WMI/passwdpolicy/pinLogin" );
log = get_kb_item( "WMI/passwdpolicy/log" );
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba, es ist kein\\nMicrosoft Windows System." );
}
else {
	if( !OSVER ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
	}
	else {
		if( !PPS || !LPS ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			if(!PPS){
				desc += NASLString( "\\nDie Passwordpolicy konnte nicht ermittelt werden." );
			}
			if(!LPS){
				desc += NASLString( "\\nDie Lockoutpolicy konnte nicht ermittelt werden." );
			}
		}
		else {
			if( ContainsString( PP, "error" ) || ContainsString( LP, "error" ) ){
				result = NASLString( "Fehler" );
				if(!log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
				}
				if(log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
				}
			}
			else {
				if( MINPA >= 1 && PHS >= 6 && LD >= 60 && RLC >= 30 && MPL >= 8 && LBC <= 3 && MAXPA <= 90 && ContainsString( "False", RLTCP ) && ContainsString( "True", PC ) && ContainsString( "False", CTP ) && PINLOGIN != "0" ){
					result = NASLString( "erfüllt" );
					desc = NASLString( "Die Kennwortrichtlinien und Kontosperrungsrichtlinien\\nentsprechen der IT-Grundschutz Maßnahme 4.048." );
				}
				else {
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Die Kennwortrichtlinien und Kontosperrungsrichtlinien\\nentsprechen nicht der IT-Grundschutz Maßnahme 4.048.\\n" );
					if(!ContainsString( "False", LP )){
						if(MINPA < 1){
							desc = desc + NASLString( "Das minimale Kennwortalter ist: " + MINPA + "\n" );
						}
						if(PHS < 6){
							desc = desc + NASLString( "Die Kennwortchronik umfasst nur " + PHS + " Kennwörter\n" );
						}
						if(LD < 60){
							desc = desc + NASLString( "Die Kontosperrdauer beträgt nur " + LD + " Minuten\n" );
						}
						if(RLC < 30){
							desc = desc + NASLString( "Die Zurücksetzungsdauer des Kontosperrungszählers\\nbeträgt nur " + RLC + " Minuten\n" );
						}
						if(MPL < 8){
							desc = desc + NASLString( "Die minimale Kennwortlänge beträgt nur: " + MPL + "\n" );
						}
						if(LBC > 3){
							desc = desc + NASLString( "Die Kontosperrungsschwelle beträgt " + LBC + "\nVersuche\n" );
						}
						if(MAXPA > 90){
							desc = desc + NASLString( "Das maximale Kennwortalter beträgt nur " + MAXPA + "\nTage\n" );
						}
						if(PINLOGIN != "0"){
							desc = desc + NASLString( "Die PIN-Anmeldung ist nicht deaktiviert (ab Windows 8, Registry-Value: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System ! AllowSignInOptions = DWORD(0) )\n" );
						}
					}
					if(!ContainsString( "False", PP )){
						if(ContainsString( "True", RLTCP )){
							desc = desc + NASLString( "-Benutzer muss sich anmelden, um Kennwort zu ändern-\nist gesetzt\n" );
						}
						if(ContainsString( "False", PC )){
							desc = desc + NASLString( "-Kennwort muss Komplexittsvoraussetzungen entsprechen-\nist nicht gesetzt\n" );
						}
						if(ContainsString( "True", CTP )){
							desc = desc + NASLString( "-Kennwörter für alle Domänenbenutzer mit umkehrbarer\nVerschlüsselung speichern- ist gesetzt\n" );
						}
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_048/result", value: result );
set_kb_item( name: "GSHB/M4_048/desc", value: desc );
set_kb_item( name: "GSHB/M4_048/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_048" );
}
exit( 0 );

