if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94236" );
	script_version( "$Revision: 10396 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.328: Sichere Grundkonfiguration eines Samba-Servers" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "GSHB/GSHB_SSH_Samba.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04328.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.328: Sichere Grundkonfiguration eines Samba-Servers

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("itg.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M4.328: Sichere Grundkonfiguration eines Samba-Servers\n";
samba = kb_smb_is_samba();
global = get_kb_item( "GSHB/SAMBA/global" );
netlogon = get_kb_item( "GSHB/SAMBA/netlogon" );
smbpasswd = get_kb_item( "GSHB/SAMBA/smbpasswd" );
secretstdb = get_kb_item( "GSHB/SAMBA/secretstdb" );
log = get_kb_item( "GSHB/SAMBA/log" );
global = tolower( global );
netlogon = tolower( netlogon );
if(global != "none" && global != "novalentrys"){
	Lst = split( buffer: global, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(ContainsString( Lst[i], "security" )){
			security = Lst[i];
		}
		if(ContainsString( Lst[i], "ntlm auth" )){
			ntlmauth = Lst[i];
		}
		if(ContainsString( Lst[i], "valid users" )){
			validusers = Lst[i];
		}
		if(ContainsString( Lst[i], "hosts allow" )){
			hostsallow = Lst[i];
		}
		if(ContainsString( Lst[i], "hosts deny" )){
			hostsdeny = Lst[i];
		}
		if(ContainsString( Lst[i], "interfaces" )){
			interfaces = Lst[i];
		}
		if(ContainsString( Lst[i], "bind interfaces only" )){
			bindinterfacesonly = Lst[i];
		}
		if(ContainsString( Lst[i], "follow symlinks" )){
			followsymlinks = Lst[i];
		}
		if(ContainsString( Lst[i], "wide links" )){
			widelinks = Lst[i];
		}
		if(ContainsString( Lst[i], "passdb backend" )){
			passdbbackend = Lst[i];
		}
	}
}
if(netlogon != "none" && netlogon != "novalentrys"){
	Lst = split( buffer: netlogon, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(ContainsString( Lst[i], "read only =" )){
			readonly = Lst[i];
		}
	}
}
if(!security){
	security = "false";
}
if(!ntlmauth){
	ntlmauth = "false";
}
if(!validusers){
	validusers = "false";
}
if(!hostsallow){
	hostsallow = "false";
}
if(!hostsdeny){
	hostsdeny = "false";
}
if(!interfaces){
	interfaces = "false";
}
if(!bindinterfacesonly){
	bindinterfacesonly = "false";
}
if(!followsymlinks){
	followsymlinks = "false";
}
if(!widelinks){
	widelinks = "false";
}
if(!readonly){
	readonly = "false";
}
if(!passdbbackend){
	passdbbackend = "false";
}
if( !samba ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft kein Samba-Dateiserver." );
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
		if( global == "none" || global == "novalentrys" ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Auf dem System wurde keine Konfiguration für einen\nSamba-Dateiserver gefunden." );
		}
		else {
			if( ContainsString( security, "share" ) || ContainsString( security, "server" ) || security == "false" ){
				result = NASLString( "nicht erfüllt" );
				if( ContainsString( security, "share" ) ) {
					desc = NASLString( "Der Sicherheitsmodus -share- darf nicht verwendet\nwerden." );
				}
				else {
					if( ContainsString( security, "server" ) ) {
						desc = NASLString( "Der Sicherheitsmodus -server- darf nicht verwendet\nwerden." );
					}
					else {
						if(security == "false"){
							desc = NASLString( "Es wurde kein Sicherheitsmodus konfiguriert." );
						}
					}
				}
			}
			else {
				if(( hostsallow == "false" && hostsdeny == "false" ) || hostsallow == "false"){
					hostsallow_res = "ne";
					hostsallow_desc = "- Samba sollte so konfiguriert werden, dass\nVerbindungen nur von als sicher geltenden Hosts und\nNetzen entgegengenommen werden.\n";
				}
				if(validusers == "false"){
					validusers_res = "ne";
					validusers_desc = "\n- Generell sollte nur ausgewählten Benutzern und\nBenutzergruppen erlaubt werden, sich mit dem Samba-\nDienst verbinden zu dürfen.\nDer Zugriff sollte daher\nin der Konfigurationsdatei smb.conf mit der Option\n-valid users- beschränkt werden.\n";
				}
				if(interfaces == "false" || !ContainsString( bindinterfacesonly, "yes" )){
					interfaces_res = "ne";
					interfaces_desc = "\n- Standardmäßig bindet sich Samba an alle verfügbaren\nNetzadressen des Systems.\nSamba sollte so konfigu-\nriert werden, dass es sich nur an als sicher geltende\nNetzadressen bindet.\n";
				}
				if(( netlogon != "false" && netlogon != "novalentrys" ) && !ContainsString( readonly, "yes" )){
					netlogon_res = "ne";
					netlogon_desc = "\n- Wird eine [netlogon] Freigabe konfiguriert, so\nsollte der freigabespezifischen Parameter\n-read only = yes- gesetzt werden.\n";
				}
				if(passdbbackend != "false"){
					if( ContainsString( passdbbackend, "tdbsam" ) ){
						if(!IsMatchRegexp( secretstdb, "-rw-------.*" )){
							passdbbackend_res = "ne";
							passdbbackend_desc = "\n- Es muss sichergestellt werden, dass ein Benutzer\nkeine Hash-Werte aus dem Backend auslesen kann. Bei\nden Backends tdbsam sollte daher nur der Benutzer\n\"root\" Lese- und Schreibzugriff auf die Datei haben,\nin denen die Benutzerinformationen abgelegt werden.\n";
						}
					}
					else {
						if(ContainsString( passdbbackend, "smbpasswd" )){
							if( !IsMatchRegexp( smbpasswd, "-rw-------.*" ) ){
								passdbbackend_res = "ne";
								passdbbackend_desc = "\n- Es muss sichergestellt werden, dass ein Benutzer\nkeine Hash-Werte aus dem Backend auslesen kann. Bei\nden Backends smbpasswd sollte daher nur der Benutzer\n\"root\" Lese- und Schreibzugriff auf die Datei haben,\nin denen die Benutzerinformationen abgelegt werden.\n";
							}
							else {
								passdbbackend_res = "ne";
								passdbbackend_desc = "\n- Es sollte von der Verwendung des smbpasswd-Backends\nabgesehen werden. Es muss sichergestellt werden, dass\nein Benutzer keine Hash-Werte aus dem Backend auslesen\nkann.\nBei den Backends smbpasswd sollte daher nur der\nBenutzer \"root\" Lese- und Schreibzugriff auf die Datei\nhaben,\nin denen die Benutzerinformationen abgelegt\nwerden.\n";
							}
						}
					}
				}
				if(!ContainsString( followsymlinks, "no" ) && !ContainsString( widelinks, "no" )){
					links_res = "ne";
					links_desc = NASLString( "\n- Schreiben die Sicherheitsrichtlinien vor, dass\nBenutzer keinen Zugriff auf Informationen\naußerhalb\nder Freigaben haben dürfen, so wird empfohlen\n-wide links = no- zu setzen.\n" );
				}
				if(ContainsString( security, "domain" ) || ContainsString( security, "ads" )){
					if(!ContainsString( ntlmauth, "no" ) || ntlmauth == "false"){
						ntlmauth_res = "ne";
						ntlmauth_desc = NASLString( "\n- Damit Samba nur NTLMv2 einsetzt, muss der Parameter\n-ntlm auth = no- in der Konfigurationsdatei smb.conf\ngesetzt werden.\n" );
					}
				}
				if( hostsallow_res == "ne" || validusers_res == "ne" || interfaces_res == "ne" || netlogon_res == "ne" || passdbbackend_res == "ne" || ntlmauth == "ne" ){
					result = NASLString( "nicht erfüllt" );
					desc = hostsallow_desc + validusers_desc + interfaces_desc + netlogon_desc + ntlmauth_desc + passdbbackend_desc + links_desc;
				}
				else {
					result = NASLString( "erfüllt" );
					desc = NASLString( "Die Grundkonfiguration Ihres Samba-Servers entspricht\nder Maßnahme 4.328." );
					if(links_res == "ne"){
						desc += NASLString( "\nBeachten Sie aber:\n" + links_desc );
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
set_kb_item( name: "GSHB/M4_328/result", value: result );
set_kb_item( name: "GSHB/M4_328/desc", value: desc );
set_kb_item( name: "GSHB/M4_328/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_328" );
}
exit( 0 );

