if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95056" );
	script_version( "$Revision: 13075 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-15 10:32:16 +0100 (Tue, 15 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M5.019: Einsatz der Sicherheitsmechanismen von sendmail" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05019.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "GSHB/GSHB_SMTP_sendmail.sc", "GSHB/GSHB_SSH_sendmail.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.019: Einsatz der Sicherheitsmechanismen von sendmail.

  Stand: 14. Erg‰nzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.019: Einsatz der Sicherheitsmechanismen von sendmail\n";
gshbm = "IT-Grundschutz M5.019: ";
DEBUG = get_kb_item( "GSHB/SENDMAIL/DEBUG" );
VRFX = get_kb_item( "GSHB/SENDMAIL/VRFX" );
EXPN = get_kb_item( "GSHB/SENDMAIL/EXPN" );
LSMAILCNF = get_kb_item( "GSHB/SENDMAIL/LSMAILCNF" );
lssendmailcnfdir = get_kb_item( "GSHB/SENDMAIL/lssendmailcnfdir" );
sendmailcnf = get_kb_item( "GSHB/SENDMAIL/sendmailcnf" );
mlocalp = get_kb_item( "GSHB/SENDMAIL/mlocalp" );
lsmlocalp = get_kb_item( "GSHB/SENDMAIL/lsmlocalp" );
lsstatusfiledir = get_kb_item( "GSHB/SENDMAIL/lsstatusfiledir" );
lsstatusfile = get_kb_item( "GSHB/SENDMAIL/lsstatusfile" );
statusfile = get_kb_item( "GSHB/SENDMAIL/statusfile" );
statusfiledir = get_kb_item( "GSHB/SENDMAIL/statusfiledir" );
fx = get_kb_item( "GSHB/SENDMAIL/fx" );
mlocal = get_kb_item( "GSHB/SENDMAIL/mlocal" );
lsforward = get_kb_item( "GSHB/SENDMAIL/lsforward" );
queuedir = get_kb_item( "GSHB/SENDMAIL/queuedir" );
lsqueuedir = get_kb_item( "GSHB/SENDMAIL/lsqueuedir" );
lsqueue = get_kb_item( "GSHB/SENDMAIL/lsqueue" );
aliases = get_kb_item( "GSHB/SENDMAIL/aliases" );
aliaspath = get_kb_item( "GSHB/SENDMAIL/aliaspath" );
incaliases = get_kb_item( "GSHB/SENDMAIL/incaliases" );
lsaliases = get_kb_item( "GSHB/SENDMAIL/lsaliases" );
lsaliasesdb = get_kb_item( "GSHB/SENDMAIL/lsaliasesdb" );
sendmailfunc = get_kb_item( "GSHB/SENDMAIL" );
log = get_kb_item( "GSHB/SENDMAIL/log" );
sendmail = get_kb_item( "sendmail/detected" );
if( !sendmail ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System konnte Sendmail nicht entdeckt werden." );
}
else {
	if( DEBUG == "error" || EXPN == "error" || VRFX == "error" ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Beim Abfragen des Sendmail-Servers konnte kein Ergebnis\nermittelt werden." );
	}
	else {
		if( DEBUG == "nosoc" || EXPN == "nosoc" || VRFX == "nosoc" ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Es konnte keine Verbindung mit dem SMTP Server\naufgenommen werden.." );
		}
		else {
			if( sendmailfunc == "error" ){
				result = NASLString( "Fehler" );
				if(!log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
				}
				if(log){
					desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
				}
			}
			else {
				if(DEBUG == "yes"){
					valcheck += "FAIL";
					desc = NASLString( "Der sendmail-Prozess wird im Debug-Modus betrieben.\n" );
				}
				if(EXPN == "yes"){
					valcheck += "FAIL";
					desc += NASLString( "Der Befehl -expn- ist verf¸gbar. Bei Version >= 8 von sendmail\nl‰sst sich der Befehle z. B. durch die Option p (privacy)\nbeim Starten abschalten.\n" );
				}
				if(VRFX == "yes"){
					valcheck += "FAIL";
					desc += NASLString( "Der Befehl -vrfx- ist verf¸gbar. Bei Version >= 8 von sendmail\nl‰sst sich der Befehle z. B. durch die Option p (privacy)\nbeim Starten abschalten.\n" );
				}
				if( !ContainsString( "none", LSMAILCNF ) ){
					if( !IsMatchRegexp( LSMAILCNF, "-rw.r..--- . root root.*" ) ){
						valcheck += "FAIL";
						desc += NASLString( "Die Datei -/etc/mail/sendmail.cf- hat nicht die in der Maﬂnahme\n5.019 geforderten Berechtigungen.\n" + LSMAILCNF + "\n" );
					}
					else {
						valcheck += "OK";
					}
					if( !IsMatchRegexp( lssendmailcnfdir, "d......--- . root root.*" ) ){
						valcheck += "FAIL";
						desc += NASLString( "Der Ordner -/etc/mail- hat nicht die in der Maﬂnahme 5.019\ngeforderten Berechtigungen.\n" + lssendmailcnfdir + "\n" );
					}
					else {
						valcheck += "OK";
					}
					if( fx == "none" ) {
						valcheck += "OK";
					}
					else {
						if(IsMatchRegexp( fx, "FX|.*" )){
							valcheck += "FAIL";
							desc += NASLString( "Die Programmform des F-Kommandos(z. B. FX|/tmp/prg) sollte\nnicht benutzt werden!.\n" + fx + "\n" );
						}
					}
					if( lsstatusfile != "none" && lsstatusfile != "nofile" && !IsMatchRegexp( lsstatusfile, "-......--- . root root.*" ) ){
						valcheck += "FAIL";
						desc += NASLString( "Die Datei -" + statusfile + "- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n" + lsstatusfile + "\n" );
					}
					else {
						valcheck += "OK";
					}
					if( !IsMatchRegexp( lsstatusfiledir, "d......--- . root root.*" ) ){
						valcheck += "FAIL";
						statusfiledir = ereg_replace( string: statusfiledir, pattern: "\n", replace: "", icase: 0 );
						desc += NASLString( "Der Ordner -" + statusfiledir + "- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n" + lsstatusfiledir + "\n" );
					}
					else {
						valcheck += "OK";
					}
					if( !IsMatchRegexp( lsaliases, "-......--- . root root.*" ) ){
						valcheck += "FAIL";
						aliaspath = ereg_replace( string: aliaspath, pattern: "\n", replace: "", icase: 0 );
						desc += NASLString( "Die Datei -" + aliaspath + "- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n" + lsaliases + "\n" );
					}
					else {
						valcheck += "OK";
					}
					if( !IsMatchRegexp( lsaliasesdb, "-......--- . root root.*" ) ){
						valcheck += "FAIL";
						desc += NASLString( "Die Datei -" + aliaspath + ".db- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n" + lsaliasesdb + "\n" );
					}
					else {
						valcheck += "OK";
					}
					if(aliases != "none"){
						Lst = split( buffer: aliases, keep: 0 );
						for(i = 0;i < Lst;i++){
							if(IsMatchRegexp( Lst[i], ".*:.*/.*/.*" )){
								aliasval += "fail";
							}
						}
						if( ContainsString( aliasval, "fail" ) ){
							valcheck += "FAIL";
							desc += NASLString( "Aus der Alias-Datei sollte jedes ausf¸hrbare Programm\nentfernt werden." );
						}
						else {
							valcheck += "OK";
						}
					}
					if(!IsMatchRegexp( lsqueuedir, "drwx...... . root root.*" )){
						valcheck += "FAIL";
						queuedir = ereg_replace( string: queuedir, pattern: "\n", replace: "", icase: 0 );
						desc += NASLString( "Der Ordner -" + queuedir + "- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n" + lsqueuedir + "\n" );
					}
					if( lsforward == "none" && lsforward == "not found" ) {
						valcheck += "OK";
					}
					else {
						Lst = split( buffer: lsforward, keep: 0 );
						for(i = 0;i < Lst;i++){
							if(IsMatchRegexp( Lst[i], "......... . .* .* .* ..-..-.. .* .*/root/.*" ) || IsMatchRegexp( Lst[i], "......... . .* .* .* ..-..-.. .* .*/bin/.*" )){
								valcheck += "FAIL";
								lsforwardcheck += Lst[i] + "\n";
							}
							if(lsforwardcheck){
								desc += NASLString( "Privilegierte Benutzer wie bin oder root sollten keine .forward\nDatei besitzen.\n" + lsforwardcheck + "\n" );
							}
							desc += NASLString( "F¸r normale Benutzer sollte die .forward-Datei nur von dem\nBesitzer beschreibbar sein und muss sich in einem Verzeichnis\nbefinden, das dem Besitzer gehˆrt. Bitte Pr¸fen Sie folgende\nErgebnisse:\n" + lsforward + "\n" );
						}
					}
					if(mlocalp != "none"){
						mlocalp = split( buffer: mlocalp, sep: "=", keep: 0 );
						valcheck += "DISPLAY";
						desc += NASLString( "Bei der Definition des Delivery Agents (z. B. Mlocal) d¸rfen\nnur absolute Pfade angegeben werden (z. B. P=/bin/mail).\nPr¸fen Sie von daher folgenden Eintrag:\n" + mlocalp[1] + "\n" );
					}
					if(lsmlocalp != "none"){
						valcheck += "DISPLAY";
						desc += NASLString( "Auﬂerdem sollte das Flag S (suid) nur gesetzt werden, wenn die\ndamit evtl. verbundenen Sicherheitsprobleme gekl‰rt sind.\nPr¸fen Sie von daher folgenden Eintrag:\n" + lsmlocalp + "\n" );
					}
					if(incaliases != "none"){
						valcheck += "DISPLAY";
						desc += NASLString( "Folgende Dateien, die von sendmail ausgewertet werden wie z. B.\n:include: in Mailing Listen, sollte nur von root beschreibbar\nsein und auch nur in root gehˆrenden Verzeichnissen stehen:\n" + incaliases + "\n" );
					}
					if(lsqueue != "noperm" && lsqueue != "none"){
						valcheck += "DISPLAY";
						desc += NASLString( "Die Queue-Dateien sollten die Berechtigung 0600 haben:\n" + lsqueue + "\n" );
					}
				}
				else {
					result = NASLString( "Fehler" );
					desc = NASLString( "Die Datei -/etc/mail/sendmail.cf- konnte nicht gefunden werden." );
				}
			}
		}
	}
}
if( ContainsString( valcheck, "FAIL" ) ){
	result = NASLString( "nicht erf¸llt" );
}
else {
	if( valcheck && ( !ContainsString( valcheck, "FAIL" ) && ContainsString( valcheck, "DISPLAY" ) ) ){
		result = NASLString( "unvollst‰ndig" );
	}
	else {
		if(valcheck && ( !ContainsString( valcheck, "FAIL" ) && !ContainsString( valcheck, "DISPLAY" ) )){
			result = NASLString( "erf¸llt" );
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M5_019/result", value: result );
set_kb_item( name: "GSHB/M5_019/desc", value: desc );
set_kb_item( name: "GSHB/M5_019/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_019" );
}
exit( 0 );

