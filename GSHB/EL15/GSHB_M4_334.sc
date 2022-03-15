if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94241" );
	script_version( "$Revision: 10396 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.334: SMB Message Signing und Samba" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "GSHB/GSHB_SSH_Samba.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04334.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.334: SMB Message Signing und Samba

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("itg.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M4.334: SMB Message Signing und Samba\n";
samba = kb_smb_is_samba();
global = get_kb_item( "GSHB/SAMBA/global" );
global = tolower( global );
log = get_kb_item( "GSHB/SAMBA/log" );
if(global != "none" && global != "novalentrys"){
	Lst = split( buffer: global, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(ContainsString( Lst[i], "client signing" )){
			clientsigning = Lst[i];
		}
		if(ContainsString( Lst[i], "server signing" )){
			serversigning = Lst[i];
		}
		if(ContainsString( Lst[i], "domain logons" )){
			domainlogons = Lst[i];
		}
		if(ContainsString( Lst[i], "domain master" )){
			domainmaster = Lst[i];
		}
	}
}
if(!clientsigning){
	clientsigning = "false";
}
if(!serversigning){
	serversigning = "false";
}
if(!domainlogons){
	domainlogons = "false";
}
if(!domainmaster){
	domainmaster = "false";
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
			desc = NASLString( "\nAuf dem System wurde keine Konfiguration für einen\nSamba-Dateiserver gefunden." );
		}
		else {
			if( ( ContainsString( clientsigning, "auto" ) || ContainsString( clientsigning, "mandatory" ) ) && ContainsString( serversigning, "yes" ) && ContainsString( domainlogons, "yes" ) ){
				result = NASLString( "erfüllt" );
				if( ContainsString( domainmaster, "no" ) ) {
					desc = NASLString( "Samba läuft als BDC." );
				}
				else {
					desc = NASLString( "Samba läuft als PDC.\n" );
				}
				if(ContainsString( clientsigning, "auto" )){
					desc += NASLString( "SMB Client signing ist auf Auto eingestellt\n" );
				}
				if(ContainsString( clientsigning, "mandatory" )){
					desc += NASLString( "SMB Client signing ist auf Mandatory eingestellt\n" );
				}
				desc += NASLString( "und Server signing ist aktiviert." );
			}
			else {
				if( ( ContainsString( clientsigning, "auto" ) || ContainsString( clientsigning, "mandatory" ) ) && ContainsString( serversigning, "no" ) && ( ContainsString( domainlogons, "no" ) || domainlogons == "false" ) ){
					result = NASLString( "erfüllt" );
					if(ContainsString( clientsigning, "auto" )){
						desc = NASLString( "SMB Client signing ist auf Auto eingestellt\n" );
					}
					if(ContainsString( clientsigning, "mandatory" )){
						desc = NASLString( "SMB Client signing ist auf Mandatory eingestellt\n" );
					}
					desc += NASLString( "und Server signing ist nicht aktiviert. Samba läuft\nals Fileserver." );
				}
				else {
					if( ( ( ContainsString( clientsigning, "no" ) || clientsigning == "false" ) || ( ContainsString( serversigning, "no" ) || serversigning == "false" ) ) && ContainsString( domainlogons, "yes" ) ){
						result = NASLString( "nicht erfüllt" );
						if( ContainsString( domainmaster, "no" ) ) {
							desc = NASLString( "Samba läuft als BDC.\n" );
						}
						else {
							desc = NASLString( "Samba läuft als PDC.\n" );
						}
						if(ContainsString( clientsigning, "no" ) || clientsigning == "false"){
							desc += NASLString( "Client signing ist nicht aktiviert.\n" );
						}
						if(ContainsString( serversigning, "no" ) || serversigning == "false"){
							desc += NASLString( "Server signing ist nicht aktiviert.\n" );
						}
					}
					else {
						if( ContainsString( clientsigning, "no" ) && ContainsString( domainlogons, "no" ) ){
							result = NASLString( "unvollständig" );
							desc = NASLString( "Samba läuft als Fileserver. Client signing ist nicht\naktiviert. Bitte prüfen Sie ob Windows Systeme auf die\nFreigaben zugreifen und aktivieren Sie ggf.\nClient signing." );
						}
						else {
							if(clientsigning == "false" && serversigning == "false" && ( domainlogons == "false" || ContainsString( domainlogons, "no" ) )){
								result = NASLString( "unvollständig" );
								desc = NASLString( "Samba läuft als Fileserver. Client und Server signing\nsind nicht konfiguriert. Bitte prüfen Sie ob Windows\nSysteme auf die Freigaben zugreifen und aktivieren Sie\nggf. Client signing." );
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
set_kb_item( name: "GSHB/M4_334/result", value: result );
set_kb_item( name: "GSHB/M4_334/desc", value: desc );
set_kb_item( name: "GSHB/M4_334/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_334" );
}
exit( 0 );

