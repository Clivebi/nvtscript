if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94191" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_prev_root_login.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten\n";
gshbm = "IT-Grundschutz M4.021: ";
ttynonconsole = get_kb_item( "GSHB/securetty/nonconsole" );
SSHDPermitRootLogin = get_kb_item( "GSHB/sshdconfig/PermitRootLogin" );
syslogsuenab = get_kb_item( "GSHB/logindefs/syslogsuenab" );
nfsexports = get_kb_item( "GSHB/nfsexports" );
nfsnorootsquash = get_kb_item( "GSHB/nfsexports/norootsquash" );
nfsrootsquash = get_kb_item( "GSHB/nfsexports/rootsquash" );
permsecuretty = get_kb_item( "GSHB/securetty/perm" );
permsshdconfig = get_kb_item( "GSHB/sshdconfig/perm" );
permlogindefs = get_kb_item( "GSHB/logindefs/perm" );
log = get_kb_item( "GSHB/securetty/log" );
uname = get_kb_item( "GSHB/uname" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( ttynonconsole == "windows" ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein." );
	}
	else {
		if(ContainsString( "error", ttynonconsole )){
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
if(result != "nicht zutreffend" && result != "Fehler"){
	if(ContainsString( "none", ttynonconsole ) || ContainsString( "none", SSHDPermitRootLogin ) || ContainsString( "none", syslogsuenab ) || ContainsString( "none", nfsexports ) || ttynonconsole == "nocat" || SSHDPermitRootLogin == "nocat" || syslogsuenab == "nocat" || nfsexports == "nocat"){
		if(ContainsString( "none", ttynonconsole ) && !IsMatchRegexp( uname, "SunOS.*" )){
			result_tty = NASLString( "Fehler" );
			desc = NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/securetty nicht gefunden werden\nkonnte.\n" );
		}
		if(ContainsString( "none", SSHDPermitRootLogin )){
			result_sshd = NASLString( "Fehler" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/ssh/sshd_config nicht gefunden\nwerden konnte.\n" );
		}
		if(ContainsString( "none", syslogsuenab ) && !IsMatchRegexp( uname, "SunOS.*" )){
			result_syslog = NASLString( "Fehler" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/login.defs nicht gefunden werden\nkonnte.\n" );
		}
		if(ContainsString( "none", nfsexports ) && !IsMatchRegexp( uname, "SunOS.*" )){
			result_nfs = NASLString( "Fehler" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/exports nicht gefunden werden\nkonnte.\n" );
		}
		if(ttynonconsole == "nocat" || SSHDPermitRootLogin == "nocat" || syslogsuenab == "nocat" || nfsexports == "nocat"){
			result_tty = NASLString( "Fehler" );
			result_nfs = NASLString( "Fehler" );
			result_sshd = NASLString( "Fehler" );
			result_nfs = NASLString( "Fehler" );
			desc = NASLString( "Fehler: Beim Testen des Systems wurde der Befehl\ncat nicht gefunden.\n" );
		}
	}
	if(!IsMatchRegexp( uname, "SunOS.*" )){
		if( ContainsString( "noperm", ttynonconsole ) ){
			result_tty = NASLString( "Fehler" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/securetty zu lesen.\n \n" );
		}
		else {
			if( ContainsString( "secure", ttynonconsole ) ){
				result_tty = "ok";
				desc += NASLString( "Beim Testen des Systems wurden keine fehlerhafte\nEinträge in der Datei /etc/securetty gefunden.\n \n" );
			}
			else {
				result_tty = "fail";
				desc += NASLString( "Fehler: Beim Testen des Systems wurden folgende zu\nentfernende Einträge in der Datei\n/etc/securetty gefunden:\n" + ttynonconsole + "\n \n" );
			}
		}
	}
	if( ContainsString( "noperm", SSHDPermitRootLogin ) ){
		result_sshd = NASLString( "Fehler" );
		desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/ssh/sshd_config zu lesen.\n \n" );
	}
	else {
		if( SSHDPermitRootLogin == "norootlogin" ){
			result_sshd = "ok";
			desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass\nPermitRootLogin in der Datei /etc/ssh/sshd_config\nauf no gesetzt ist.\n \n" );
		}
		else {
			if(SSHDPermitRootLogin == "rootlogin"){
				result_sshd = "fail";
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass PermitRootLogin in der Datei\n/etc/ssh/sshd_config auf yes gesetzt ist.\nÄndern Sie den Wert wenn möglich auf no.\n \n" );
			}
		}
	}
	if(!IsMatchRegexp( uname, "SunOS.*" )){
		if( ContainsString( "noperm", syslogsuenab ) ){
			result_syslog = NASLString( "Fehler" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/login.defs zu lesen.\n \n" );
		}
		else {
			if( syslogsuenab == "syslogsuenab" ){
				result_syslog = "ok";
				desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass\nSYSLOG_SU_ENAB in der Datei /etc/login.defs\nauf yes gesetzt ist.\n \n" );
			}
			else {
				if(syslogsuenab == "nosyslogsuenab"){
					result_syslog = "fail";
					desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass SYSLOG_SU_ENAB in der Datei /etc/login.defs auf\nno gesetzt ist. Ändern Sie den Wert wenn möglich\nauf yes.\n \n" );
				}
			}
		}
	}
	if(!IsMatchRegexp( uname, "SunOS.*" )){
		if( ContainsString( "noperm", nfsexports ) ){
			result_nfs = NASLString( "Fehler" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/exports zu lesen.\n \n" );
		}
		else {
			if( nfsnorootsquash != "none" ){
				result_nfs = "fail";
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass der Eintrag root_squash in der Datei /etc/exports\nbei folgenden Einträgen fehlt:\n" + nfsnorootsquash + "\n \n" );
			}
			else {
				if( nfsnorootsquash == "none" && nfsrootsquash != "none" ){
					result_nfs = "ok";
					desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass der\nEintrag root_squash in der Datei /etc/exports bei\nallen Einträgen gesetzt ist.\n \n" );
				}
				else {
					if(nfsnorootsquash == "none" && nfsrootsquash == "none"){
						result_nfs = "ok";
						desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass keine\nEinträge/Freigaben in der Datei /etc/exports gibt.\n \n" );
					}
				}
			}
		}
	}
	if(permsecuretty == "none" || permsshdconfig == "none" || permlogindefs == "none"){
		if(permsecuretty == "none" && !IsMatchRegexp( uname, "SunOS.*" )){
			result_permsecuretty = NASLString( "Fehler" );
			if(result_tty != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/securetty nicht gefunden\nwerden konnte.\n \n" );
			}
		}
		if(permsshdconfig == "none"){
			result_permsshdconfig = NASLString( "Fehler" );
			if(result_sshd != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/ssh/sshd_config nicht gefunden\nwerden konnte.\n \n" );
			}
		}
		if(permlogindefs == "none" && !IsMatchRegexp( uname, "SunOS.*" )){
			result_permlogindefs = NASLString( "Fehler" );
			if(result_syslog != "Fehler"){
				desc += NASLString( "Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/login.defs nicht gefunden\nwerden konnte.\n \n" );
			}
		}
	}
	if(permsecuretty != "none"){
		if( IsMatchRegexp( permsecuretty, "-rw-(r|-)--(r|-)--.*" ) ){
			result_permsecuretty = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Datei\n/etc/securetty folgende korrekte Sicherheits-\neinstellungen festgestellt:\n" + permsecuretty + "\n \n" );
		}
		else {
			result_permsecuretty = NASLString( "fail" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Datei\n/etc/securetty folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: " + permsecuretty + "\nBitte ändern Sie diese auf \"-rw-r--r--\".\n \n" );
		}
	}
	if(permsshdconfig != "none"){
		if( IsMatchRegexp( permsshdconfig, "-rw-(r|-)--(r|-)--.*" ) ){
			result_permsshdconfig = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Datei\n/etc/ssh/sshd_config folgende korrekte Sicherheitsein-\nstellungen festgestellt: " + permsshdconfig + "\n \n" );
		}
		else {
			result_permsshdconfig = NASLString( "fail" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Datei\n/etc/ssh/sshd_config folgende fehlerhafte Sicherheits-\neinstellungen festgestellt: " + permsshdconfig + "\nBitte ändern Sie diese auf \"-rw-r--r--\".\n \n" );
		}
	}
	if(permlogindefs != "none"){
		if( IsMatchRegexp( permlogindefs, "-rw-(r|-)--(r|-)--.*" ) ){
			result_permlogindefs = NASLString( "ok" );
			desc += NASLString( "Beim Testen des Systems wurden für die Datei\n/etc/login.defs folgende korrekte Sicherheitsein-\nstellungen festgestellt: " + permlogindefs + "\n \n" );
		}
		else {
			result_permlogindefs = NASLString( "fail" );
			desc += NASLString( "Fehler: Beim Testen des Systems wurden für die Datei\n/etc/login.defs folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: " + permlogindefs + "\nBitte ändern Sie diese auf \"-rw-r--r--\".\n \n" );
		}
	}
	if( !result && ( result_tty == "fail" || result_sshd == "fail" || result_syslog == "fail" || result_nfs == "fail" || result_permsecuretty == "fail" || result_permsshdconfig == "fail" || result_permlogindefs == "fail" ) ) {
		result = NASLString( "nicht erfüllt" );
	}
	else {
		if( !result && ( result_tty == "Fehler" || result_sshd == "Fehler" || result_syslog == "Fehler" || result_nfs == "Fehler" || result_permsecuretty == "Fehler" || result_permsshdconfig == "Fehler" || result_permlogindefs == "Fehler" ) ) {
			result = NASLString( "Fehler" );
		}
		else {
			if(!result && result_tty == "ok" && result_sshd == "ok" && result_syslog == "ok" && result_nfs == "ok" && result_permsecuretty == "ok" && result_permsshdconfig == "ok" && result_permlogindefs == "ok"){
				result = NASLString( "erfüllt" );
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_021/result", value: result );
set_kb_item( name: "GSHB/M4_021/desc", value: desc );
set_kb_item( name: "GSHB/M4_021/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_021" );
}
exit( 0 );

