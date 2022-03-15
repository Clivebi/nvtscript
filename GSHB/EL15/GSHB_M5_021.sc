if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95058" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_r-tools.sc", "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_TFTP_s-option.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec\n";
gshbm = "IT-Grundschutz M5.021: ";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
inetdconf = get_kb_item( "GSHB/R-TOOL/inetdconf" );
ftpusers = get_kb_item( "GSHB/R-TOOL/ftpusers" );
netrc = get_kb_item( "GSHB/R-TOOL/netrc" );
log = get_kb_item( "GSHB/R-TOOL/log" );
tftp = get_kb_item( "GSHB/TFTP/s-option" );
if(!ContainsString( "noentry", inetdconf ) && !ContainsString( "none", inetdconf )){
	Lst = split( buffer: inetdconf, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(IsMatchRegexp( Lst[i], "^ftp.*" )){
			val_ftp = "yes";
		}
		if(IsMatchRegexp( Lst[i], "^tftp.*" )){
			val_tftp = "yes";
		}
		if(IsMatchRegexp( Lst[i], "^telnet.*" )){
			val_telnet = "yes";
		}
	}
}
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( inetdconf == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( inetdconf == "error" ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( netrc != "not found" || val_tftp == "yes" || tftp == "fail" || val_telnet == "yes" || ( val_ftp == "yes" && ftpusers == "noentry" ) ){
				result = NASLString( "nicht erfüllt" );
				if(netrc != "not found"){
					desc = NASLString( "Es muss sichergestellt werden, dass keine .netrc-Dateien in den\nBenutzerverzeichnissen vorhanden sind oder dass sie leer sind\nund der Benutzer keine Zugriffsrechte auf diese hat. Folgende\n.netrc-Dateien wurden gefunden:\n" + netrc );
				}
				if(val_tftp == "yes"){
					desc += NASLString( "\nDer Einsatz des Daemons tftpd muss verhindert werden (z. B.\ndurch Entfernen\ndes entsprechenden Eintrags in der Datei\n/etc/inetd.conf)." );
				}
				if(val_ftp == "yes"){
					desc += NASLString( "\nFühren Sie bitte einen NVT-Scan aus, um mögliche Sicherheits-\nlücken im installierten FTP-Server zu finden." );
				}
				if(val_ftp == "yes" && ftpusers == "noentry"){
					desc += NASLString( "Es konnten keine Einträge in der Datei -/etc/ftpusers- gefunden\nwerden. In die Datei /etc/ftpusers sollten alle Benutzernamen\neingetragen werden, für die ein ftp-Zugang nicht erlaubt werden\nsoll. Hierzu gehören z. B. root, uucp und bin." );
				}
				if(val_ftp == "yes" && ftpusers != "none"){
					desc += NASLString( "\nIn die Datei /etc/ftpusers sollten alle Benutzernamen\neingetragen werden, für die ein\nftp-Zugang nicht erlaubt\nwerden soll. Hierzu gehören z. B. root, uucp und bin. Folgende\nEinträge wurden in der Datei -/etc/ftpusers- gefunden: \n" + ftpusers );
				}
				if(val_telnet == "yes"){
					desc += NASLString( "\nAuf dem Zilesystem wurde ein Telnet-Server in der\n-/etc/inetd.conf- gefunden. Sie sollten SSH anstelle von\ntelnet nutzen." );
				}
				if(tftp == "fail"){
					desc += NASLString( "Es muss sichergestellt sein, dass beim Einsatz von tftp den\nBenutzern aus dem Login-Verzeichnis nur eingeschränkte\nDateizugriffe möglich sind. In diesem Fall war es möglich auf\ndie Datei -/etc/passwd- zuzugreifen. Starten Sie den\ntftp-Daemon mit der Option -s verzeichnis." );
				}
			}
			else {
				result = NASLString( "erfüllt" );
				desc = NASLString( "Das System entspricht der Maßnahme 5.021." );
				if(val_ftp == "yes"){
					desc += NASLString( "\nFühren Sie bitte einen NVT-Scan aus, um mögliche\nSicherheitslücken im installierten FTP-Server zu finden." );
				}
				if(val_ftp == "yes" && ftpusers != "none"){
					desc += NASLString( "\n\nIn die Datei /etc/ftpusers sollten alle Benutzernamen\neingetragen werden, für die ein ftp-Zugang nicht erlaubt werden\nsoll. Hierzu gehören z. B. root, uucp und bin. Folgende\nEinträge wurden in der Datei -/etc/ftpusers- gefunden: \n" + ftpusers );
				}
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M5_021/result", value: result );
set_kb_item( name: "GSHB/M5_021/desc", value: desc );
set_kb_item( name: "GSHB/M5_021/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_021" );
}
exit( 0 );

