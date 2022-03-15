if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95065" );
	script_version( "2020-03-26T13:48:10+0000" );
	script_tag( name: "last_modification", value: "2020-03-26 13:48:10 +0000 (Thu, 26 Mar 2020)" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IT-Grundschutz M5.064: Secure Shell" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05064.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "ssh_detect.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.064: Secure Shell.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
require("ssh_func.inc.sc");
require("version_func.inc.sc");
name = "IT-Grundschutz M5.064: Secure Shell\n";
gshbm = "IT-Grundschutz M5.064: ";
port = kb_ssh_transport();
sock = ssh_login_or_reuse_connection();
if( !sock ){
	sshsock = "no";
}
else {
	if(sock){
		sshsock = "yes";
		close( sock );
	}
}
telnet = get_kb_item( "Services/telnet" );
sshbanner = ssh_get_serverbanner( port: port );
if( sshbanner ){
	sshbanner = tolower( sshbanner );
	version = eregmatch( pattern: "ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string: sshbanner );
}
else {
	sshbanner = "none";
}
if( sshbanner == "none" && sshsock == "no" ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Es wurde kein SSH-Server gefunden" );
}
else {
	if( sshbanner == "none" && sshsock == "yes" ){
		result = NASLString( "unvollständig" );
		desc = NASLString( "Es wurde ein SSH-Server gefunden. Allerdings konnte weder der\\nTyp noch die Version erkannt werden." );
	}
	else {
		if( ContainsString( sshbanner, "openssh" ) ){
			if( telnet ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Es wurde auf Port " + port + ", folgender SSH-Server gefunden:\n" + sshbanner + "\nZusätzlich scheint auf Port 23 ein Telnet Server zu laufen.\nNach Möglichkeit sollten alle anderen Protokolle, deren\nFunktionalitäten durch SSH abgedeckt werden, vollständig\nabgeschaltet werden." );
			}
			else {
				if( version_is_less( version: version[1], test_version: "5.2" ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Es wurde auf Port " + port + ", folgender SSH-Server gefunden:\n" + sshbanner + "\nVersionen vor OpenSSH 5.2 sind verwundbar." );
				}
				else {
					result = NASLString( "erfüllt" );
					desc = NASLString( "Es wurde auf Port " + port + ", folgender SSH-Server gefunden:\n" + sshbanner + "\nVersionen vor OpenSSH 5.2 sind verwundbar." );
				}
			}
		}
		else {
			if( telnet ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Es wurde auf Port " + port + ", folgender SSH-Server gefunden:\n" + sshbanner + "\nZusätzlich scheint auf Port 23 ein Telnet Server zu laufen.\nNach Möglichkeit sollten alle anderen Protokolle, deren\nFunktionalitäten durch SSH abgedeckt werden,\nvollständig abgeschaltet werden." );
			}
			else {
				result = NASLString( "unvollständig" );
				desc = NASLString( "Es wurde auf Port " + port + ", folgender SSH-Server gefunden:\n" + sshbanner + "\nIm Moment wird nur auf OpenSSH Server getestet.\nVersionen vor OpenSSH 5.2 sind verwundbar." );
			}
		}
	}
}
set_kb_item( name: "GSHB/M5_064/result", value: result );
set_kb_item( name: "GSHB/M5_064/desc", value: desc );
set_kb_item( name: "GSHB/M5_064/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_064" );
}
exit( 0 );

