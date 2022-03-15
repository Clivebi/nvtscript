if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94240" );
	script_version( "$Revision: 11531 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-21 20:50:24 +0200 (Fri, 21 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "gather-package-list.sc", "GSHB/GSHB_SSH_fstab.sc", "GSHB/GSHB_SSH_Samba.sc", "GSHB/GSHB_SSH_nsswitch.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04333.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("itg.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba\n";
samba = kb_smb_is_samba();
global = get_kb_item( "GSHB/SAMBA/global" );
reiserfs = get_kb_item( "GSHB/FSTAB/reiserfs" );
global = tolower( global );
log = get_kb_item( "GSHB/SAMBA/log" );
SSHUNAME = get_kb_item( "ssh/login/uname" );
passwd = get_kb_item( "GSHB/nsswitch/passwd" );
group = get_kb_item( "GSHB/nsswitch/group" );
if(samba || ( SSHUNAME && ( !ContainsString( SSHUNAME, "command not found" ) && !ContainsString( SSHUNAME, "CYGWIN" ) ) )){
	rpms = get_kb_item( "ssh/login/packages" );
	if( rpms ){
		pkg1 = "winbind";
		pat1 = NASLString( "ii  (", pkg1, ") +([0-9]:)?([^ ]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
	}
	else {
		rpms = get_kb_item( "ssh/login/rpms" );
		tmp = split( buffer: rpms, keep: 0 );
		if(max_index( tmp ) <= 1){
			rpms = ereg_replace( string: rpms, pattern: ";", replace: "\n" );
		}
		pkg1 = "winbind";
		pat1 = NASLString( "(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
	}
}
if( desc1 ) {
	winbind = "yes";
}
else {
	winbind = "no";
}
if(global != "none" && global != "novalentrys"){
	Lst = split( buffer: global, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(ContainsString( Lst[i], "security" )){
			security = Lst[i];
		}
		if(ContainsString( Lst[i], "idmap backend" )){
			idmapbackend = Lst[i];
		}
		if(ContainsString( Lst[i], "template homedir" )){
			templatehd = Lst[i];
		}
		if(ContainsString( Lst[i], "idmap domains" )){
			idmapdomains = Lst[i];
		}
		if(ContainsString( Lst[i], "idmap config" )){
			idmapconfig += Lst[i] + "\n";
		}
	}
}
if(!security){
	security = "false";
}
if(!idmapbackend){
	idmapbackend = "false";
}
if(!templatehd){
	templatehd = "false";
}
if(!idmapdomains){
	idmapdomains = "false";
}
if(!idmapconfig){
	idmapconfig = "false";
}
if(!passwd){
	passwd = "false";
}
if(!group){
	group = "false";
}
if( !samba ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft kein Samba-Dateiserver." );
}
else {
	if( winbind == "no" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Auf dem System ist winbind nicht installiert." );
	}
	else {
		if( !ContainsString( passwd, "winbind" ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Auf dem System ist winbind über /etc/nsswitch.conf\nnicht eingebunden." );
		}
		else {
			if( global == "error" ){
				result = NASLString( "Fehler" );
				if(!log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
				}
				if(log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
				}
			}
			else {
				if( !ContainsString( security, "domain" ) && !ContainsString( security, "ads" ) ){
					result = NASLString( "nicht zutreffend" );
					desc = NASLString( "Der Samba Server auf dem System läuft nicht im\n-domain- oder -ads- Security-Modus." );
				}
				else {
					if( ( idmapbackend == "false" || idmapbackend == "tdb" ) && reiserfs != "noreiserfs" ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Auf dem System läuft folgende Partition mit ReiserFS:\n" + reiserfs + "\nIhr -idmap backend- ist auf tdb eingestellt.\nSämtliche Samba-Datenbanken im TDB-Format sollten auf einer\nPartition gespeichert werden, die nicht ReiserFS als\nDateisystem verwendet." );
					}
					else {
						if( templatehd == "false" || !ContainsString( templatehd, "/%d/%u" ) ){
							result = NASLString( "nicht erfüllt" );
							desc = NASLString( "Die Domäne des Benutzers sollte in den Pfad seines\nHeimatverzeichnisses aufgenommen werden. Diese\nMaßname verhindert Namenskollisionen bei\nVertrauensstellungen." );
						}
						else {
							if( idmapbackend == "false" || idmapbackend == "tdb" ){
								result = NASLString( "erfüllt" );
								desc = NASLString( "Existieren Vertrauensstellungen zwischen Domänen im\nInformationsverbund, so muss eines der folgenden ID-\nMapping-Backends verwendet werden:\n- Backend rid mit idmap domains Konfiguration.\n- Backend ldap mit idmap domains Konfiguration.\n- Backend ad.\n- Backend nss." );
							}
							else {
								if( ContainsString( idmapbackend, "rid" ) || ContainsString( idmapbackend, "ldap" ) ){
									result = NASLString( "erfüllt" );
									if( ContainsString( idmapbackend, "rid" ) && idmapdomains != "false" && idmapconfig != "false" ) {
										desc = NASLString( "Sie benutzen das ID-Mapping-Backend -rid- mit\nfolgender Konfiguration:\n" + idmapdomains + idmapconfig );
									}
									else {
										if( ContainsString( idmapbackend, "ldap" ) && idmapdomains != "false" && idmapconfig != "false" ) {
											desc = NASLString( "Sie benutzen das ID-Mapping-Backend -ldap- mit\nfolgender Konfiguration:\n" + idmapdomains + idmapconfig );
										}
										else {
											if( ContainsString( idmapbackend, "rid" ) && ( idmapdomains == "false" || idmapconfig == "false" ) ) {
												desc = NASLString( "Sie benutzen das ID-Mapping-Backend -rid-.\nExistieren Vertrauensstellungen zwischen Domänen im\nInformationsverbund,so muss -idmap domains-\nkonfiguriert werden." );
											}
											else {
												if(ContainsString( idmapbackend, "ldap" ) && ( idmapdomains == "false" || idmapconfig == "false" )){
													desc = NASLString( "Sie benutzen das ID-Mapping-Backend -ldap-.\nExistieren Vertrauensstellungen zwischen Domänen im\nInformationsverbund, so muss -idmap domains-\nkonfiguriert werden." );
												}
											}
										}
									}
								}
								else {
									result = NASLString( "erfüllt" );
									if( ContainsString( idmapbackend, "nss" ) ) {
										desc = NASLString( "Sie benutzen das ID-Mapping-Backend -nss-" );
									}
									else {
										if(ContainsString( idmapbackend, "ad" )){
											desc = NASLString( "Sie benutzen das ID-Mapping-Backend -ad-" );
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
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_333/result", value: result );
set_kb_item( name: "GSHB/M4_333/desc", value: desc );
set_kb_item( name: "GSHB/M4_333/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_333" );
}
exit( 0 );

