if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94180" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.009: Einsatz der Sicherheitsmechanismen von X-Window" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04009.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_xwindow.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.009: Einsatz der Sicherheitsmechanismen von X-Window.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.009: Einsatz der Sicherheitsmechanismen von X-Window\n";
gshbm = "IT-Grundschutz M4.009: ";
sshd = get_kb_item( "GSHB/xwindow/sshd" );
sshdlow = tolower( sshd );
lsxhost = get_kb_item( "GSHB/xwindow/lsxhost" );
log = get_kb_item( "GSHB/xwindow/log" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( sshd == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if( ContainsString( "error", sshd ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
		else {
			if( ContainsString( "none", sshd ) ){
				result = NASLString( "Fehler" );
				desc = NASLString( "Beim Testen des Systems wurde festgestellt, das\n/etc/ssh/sshd_config nicht gefunden wurde!" );
			}
			else {
				if( ContainsString( "nogrep", sshd ) ){
					result = NASLString( "Fehler" );
					desc += NASLString( "Beim Testen des Systems wurde der Befehl\ngrep nicht gefunden." );
				}
				else {
					if( ContainsString( "noperm", sshd ) ){
						result = NASLString( "Fehler" );
						desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass Sie\nkeine Berechtigung haben die Datei\n/etc/ssh/sshd_config zu lesen." );
					}
					else {
						if( IsMatchRegexp( lsxhost, ".........x .*" ) ){
							result = NASLString( "nicht erfüllt" );
							desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass\nnormale Benutzer den Befehl /usr/bin/xhost auführen\nkönnen. Folgende Einstellungen wurden vorgefunden:\n" + lsxhost );
						}
						else {
							if( IsMatchRegexp( sshdlow, ".*#.*x11forwarding" ) || IsMatchRegexp( sshdlow, "x11forwarding[ \t]+no.*" ) ){
								result = NASLString( "nicht erfüllt" );
								desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass\nX11Forwarding in der Datei /etc/ssh/sshd_config nicht\naktiviert ist.\nFolgende Einstellungen wurden vorgefunden:\n" + sshd );
							}
							else {
								result = NASLString( "erfüllt" );
								if( !ContainsString( "noxhost", lsxhost ) ) {
									desc = NASLString( "X11Forwarding wurde in der Datei /etc/ssh/sshd_config\naktiviert und normale Benutzer haben keine\nBerechtigung /usr/bin/xhost auszuführen:\nEinstellungen /etc/ssh/sshd_config: " + sshd + "\nEinstellungen für /usr/bin/xhost: " + lsxhost + "\nBitte prüfen Sie auch local die XHOST Tabelle." );
								}
								else {
									desc = NASLString( "X11Forwarding wurde in der Datei /etc/ssh/sshd_config\naktiviert\nEinstellungen /etc/ssh/sshd_config: " + sshd + "\nBitte prüfen Sie auch local die XHOST Tabelle." );
								}
							}
						}
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_009/result", value: result );
set_kb_item( name: "GSHB/M4_009/desc", value: desc );
set_kb_item( name: "GSHB/M4_009/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_013" );
}
exit( 0 );

