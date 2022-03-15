if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94230" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.305: Einsatz von Speicherbeschränkungen (Quotas)" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04305.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_quota.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.305: Einsatz von Speicherbeschränkungen (Quotas).

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.305: Einsatz von Speicherbeschränkungen (Quotas)\n";
gshbm = "IT-Grundschutz M4.305: ";
uname = get_kb_item( "GSHB/quota/uname" );
fstab = get_kb_item( "GSHB/quota/fstab" );
user = get_kb_item( "GSHB/quota/user" );
group = get_kb_item( "GSHB/quota/group" );
log = get_kb_item( "GSHB/quota/log" );
zfsquota = get_kb_item( "GSHB/quota/zfsquota" );
ufsquota = get_kb_item( "GSHB/quota/ufsquota" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Folgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( fstab == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Das System scheint ein Windows-System zu sein." );
	}
	else {
		if( IsMatchRegexp( uname, "SunOS.*" ) ){
			if( ContainsString( "norepquota", ufsquota ) && ContainsString( "nozfs", zfsquota ) ){
				result = NASLString( "Fehler" );
				desc = NASLString( "Auf dem System konnte weder der Befehl \"repquota -va\" noch der\nBefehl \"zfs get quota\", zum ermitteln der Quotaeinstellungen,\nausgeführt werden." );
			}
			else {
				if( ContainsString( "noquota", ufsquota ) && ContainsString( "noquota", zfsquota ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Auf dem System konnten keine Quotaeinstellungen\ngefunden werden." );
				}
				else {
					if( ( !ContainsString( "noquota", ufsquota ) && !ContainsString( "norepquota", ufsquota ) ) || ( !ContainsString( "noquota", zfsquota ) && !ContainsString( "nozfs", zfsquota ) ) ){
						result = NASLString( "erfüllt" );
						desc = NASLString( "Auf dem System konnten folgende Volumes mit\nQuotaeinstellungen gefunden werden:" );
						if(!ContainsString( "noquota", ufsquota ) && !ContainsString( "norepquota", ufsquota )){
							desc += NASLString( "\n" + ufsquota );
						}
						if(!ContainsString( "noquota", zfsquota ) && !ContainsString( "nozfs", zfsquota )){
							desc += NASLString( "\n" + zfsquota );
						}
					}
					else {
						result = NASLString( "Fehler" );
						if(!log){
							desc = NASLString( "Beim Testen des Systems trat ein unbekannter\nFehler auf." );
						}
						if(log){
							desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
						}
					}
				}
			}
		}
		else {
			if( ContainsString( "error", fstab ) ){
				result = NASLString( "Fehler" );
				if(!log){
					desc = NASLString( "Beim Testen des Systems trat ein unbekannter\nFehler auf." );
				}
				if(log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
				}
			}
			else {
				if( ContainsString( "none", fstab ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Auf dem System konnten keine Quotaeinstellungen\ngefunden werden." );
				}
				else {
					if( ( ( !ContainsString( "none", user ) && !ContainsString( "nols", user ) ) || ( !ContainsString( "none", group ) && !ContainsString( "nols", group ) ) ) && ( !ContainsString( "none", fstab ) && fstab != "nogrep" ) ){
						result = NASLString( "erfüllt" );
						desc = NASLString( "Auf dem System konnten folgende Volumes mit Quota-\neinstellungen gefunden werden:\n" + fstab );
					}
					else {
						if(ContainsString( "nols", user ) || ContainsString( "nols", group ) || ContainsString( "nogrep", fstab )){
							result = NASLString( "Fehler" );
							if(ContainsString( "nols", user ) || ContainsString( "nols", group )){
								desc = NASLString( "Beim Testen des Systems wurde der Befehl ls\nnicht gefunden.\n" );
							}
							if(ContainsString( "nogrep", fstab )){
								desc += NASLString( "Beim Testen des Systems wurde der Befehl grep\nnicht gefunden." );
							}
						}
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_305/result", value: result );
set_kb_item( name: "GSHB/M4_305/desc", value: desc );
set_kb_item( name: "GSHB/M4_305/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_305" );
}
exit( 0 );

