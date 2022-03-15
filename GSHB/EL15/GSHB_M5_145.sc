if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95075" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M5.145: Sicherer Einsatz von CUPS" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05145.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_SSH_cups.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.145: Sicherer Einsatz von CUPS.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.145: Sicherer Einsatz von CUPS\n";
gshbm = "GSHB Maßnahme 5.145: ";
cupsd = get_kb_item( "GSHB/cupsd" );
cupsclient = get_kb_item( "GSHB/cupsclient" );
log = get_kb_item( "GSHB/cupsd/log" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( ContainsString( "windows", cupsd ) ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System ist ein Windows-System." );
	}
	else {
		if( ContainsString( "error", cupsd ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
		else {
			if( ContainsString( "nocupsd", cupsd ) && ContainsString( "nocupsclient", cupsclient ) ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Weder CUPS noch der CPUS-Client konnten auf dem System\ngefunden werden." );
			}
			else {
				ServerName = egrep( string: cupsclient, pattern: "^.*ServerName", icase: 0 );
				Lst = split( buffer: ServerName, keep: 0 );
				ServerName = "";
				for(i = 0;i < max_index( Lst );i++){
					if(IsMatchRegexp( Lst[i], ".*#.*(S|s)(E|e)(R|r)(V|v)(E|e)(R|r)(N|n)(A|a)(M|m)(E|e).*" )){
						continue;
					}
					ServerName += Lst[i] + "\n";
				}
				Encryption = egrep( string: cupsclient, pattern: "^.*Encryption", icase: 0 );
				Lst = split( buffer: Encryption, keep: 0 );
				Encryption = "";
				for(i = 0;i < max_index( Lst );i++){
					if(IsMatchRegexp( Lst[i], ".*#.*(E|e)(N|n)(C|c)(R|r)(Y|y)(P|p)(T|t)(I|i)(O|o)(N|n).*" )){
						continue;
					}
					Encryption += Lst[i] + "\n";
				}
				Listen = egrep( string: cupsd, pattern: "^.*Listen", icase: 0 );
				Lst = split( buffer: Listen, keep: 0 );
				Listen = "";
				for(i = 0;i < max_index( Lst );i++){
					if(IsMatchRegexp( Lst[i], ".*#.*(L|l)(I|i)(S|s)(T|t)(E|e)(N|n).*" )){
						continue;
					}
					Listen += Lst[i] + "\n";
				}
				Browsing = egrep( string: cupsd, pattern: "^.*Browsing", icase: 0 );
				Lst = split( buffer: Browsing, keep: 0 );
				Browsing = "";
				for(i = 0;i < max_index( Lst );i++){
					if(IsMatchRegexp( Lst[i], ".*#.*(B|b)(R|r)(O|o)(W|w)(S|s)(I|i)(N|n)(G|g).*" )){
						continue;
					}
					Browsing += Lst[i] + "\n";
				}
				LogLevel = egrep( string: cupsd, pattern: "^.*LogLevel", icase: 0 );
				Lst = split( buffer: LogLevel, keep: 0 );
				LogLevel = "";
				for(i = 0;i < max_index( Lst );i++){
					if(IsMatchRegexp( Lst[i], ".*#.*(L|l)(O|o)(G|g)(L|l)(E|e)(V|v)(E|e)(L|l).*" )){
						continue;
					}
					LogLevel += Lst[i] + "\n";
				}
				PreserveJobs = egrep( string: cupsd, pattern: "^.*PreserveJobs", icase: 0 );
				Lst = split( buffer: PreserveJobs, keep: 0 );
				PreserveJobs = "";
				for(i = 0;i < max_index( Lst );i++){
					if(IsMatchRegexp( Lst[i], ".*#.*(P|p)(R|r)(E|e)(S|s)(E|e)(R|r)(V|v)(E|e)(J|j)(O|o)(B|b)(S|s).*" )){
						continue;
					}
					PreserveJobs += Lst[i] + "\n";
				}
				DefaultAuthType = egrep( string: cupsd, pattern: "^.*DefaultAuthType", icase: 0 );
				Lst = split( buffer: DefaultAuthType, keep: 0 );
				DefaultAuthType = "";
				for(i = 0;i < max_index( Lst );i++){
					if(IsMatchRegexp( Lst[i], ".*#.*(D|d)(E|e)(F|f)(A|a)(U|u)(L|l)(T|t)(A|a)(U|u)(T|t)(H|h)(T|t)(Y|y)(P|p)(E|e).*" )){
						continue;
					}
					DefaultAuthType += Lst[i] + "\n";
				}
				Lst = split( buffer: cupsd, keep: 0 );
				for(i = 0;i < max_index( Lst );i++){
					AdminLst += Lst[i] + ";";
				}
				Admin = eregmatch( string: AdminLst, pattern: "(.*)(<Location /admin>;.*</Location>;)(.*)", icase: 0 );
				AdminLst = "";
				for(i = 0;i < max_index( Admin );i++){
					if(ereg( string: Admin[i], pattern: "^ *<Location /admin>.*", icase: 0 )){
						Adminconf += Admin[i];
					}
				}
				if( !Adminconf || Adminconf == "" ) {
					AdminResult = "none";
				}
				else {
					AdminResult = ereg_replace( string: Adminconf, pattern: ";", replace: "\n" );
				}
				if(!ServerName){
					ServerName = "none";
				}
				if(!Encryption){
					Encryption = "none";
				}
				if(!Listen){
					Listen = "none";
				}
				if(!Browsing){
					Browsing = "none";
				}
				if(!LogLevel){
					LogLevel = "none";
				}
				if(!PreserveJobs){
					PreserveJobs = "none";
				}
				if(!AdminResult){
					AdminResult = "none";
				}
				if(!DefaultAuthType){
					DefaultAuthType = "none";
				}
				if( ContainsString( "nocupsd", cupsd ) && !ContainsString( "nocupsclient", cupsclient ) ){
					if( ContainsString( "no client.conf", cupsclient ) ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-\nClient installiert ist. Allerdings wurde die Datei\n/etc/cups/client.conf nicht gefunden. Demnach kann das System\nnicht entsprechend Massnahme 5.145 konfiguriert sein." );
					}
					else {
						if( ContainsString( "empty", cupsclient ) ){
							result = NASLString( "nicht erfüllt" );
							desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-\nClient installiert ist. Allerdings ist die Datei\n/etc/cups/client.conf leer. Demnach kann das System nicht\nentsprechend Massnahme 5.145 konfiguriert sein." );
						}
						else {
							if( ContainsString( "none", ServerName ) || ContainsString( "none", Encryption ) ){
								result = NASLString( "nicht erfüllt" );
								if(ContainsString( "none", ServerName ) && !ContainsString( "none", Encryption )){
									desc = NASLString( "Beim Testen des Systems wurde in der Datei\n/etc/cups/client.conf, der Eintrag -ServerName- nicht gefunden." );
								}
								if(!ContainsString( "none", ServerName ) && ContainsString( "none", Encryption )){
									desc = NASLString( "Beim Testen des Systems wurde in der Datei\n/etc/cups/client.conf, der Eintrag -Encryption- nicht gefunden." );
								}
								if(ContainsString( "none", ServerName ) && ContainsString( "none", Encryption )){
									desc = NASLString( "Beim Testen des Systems wurde in der Datei\n/etc/cups/client.conf, die Einträge -ServerName- und\n-Encryption- nicht gefunden." );
								}
							}
							else {
								if(!ContainsString( "none", ServerName ) && !ContainsString( "none", Encryption )){
									if( ContainsString( Encryption, "lways" ) ){
										result = NASLString( "unvollständig" );
										desc = NASLString( "Beim Testen des Systems wurden folgende Einträge in der Datei\n/etc/cups/client.conf, gefunden:\n" + ServerName + "\n" + Encryption + "\nBitte prüfen Sie, ob die Option -ServerName- den Anforderungen\nder Maßnahme 5.145 genügt." );
									}
									else {
										result = NASLString( "nicht erfüllt" );
										desc = NASLString( "Beim Testen des Systems wurden folgende Einträge in der Datei\n/etc/cups/client.conf, gefunden:\n" + ServerName + "\n" + Encryption + "\nDie Option -Encryption- sollte auf -Always- gesetzt sein.\nBitte prüfen Sie, ob die Option -ServerName- den Anforderungen\nder Maßnahme 5.145 genügt." );
									}
								}
							}
						}
					}
				}
				else {
					if( !ContainsString( "nocupsd", cupsd ) && ContainsString( "nocupsclient", cupsclient ) ){
						if( ContainsString( "no cupsd.conf", cupsd ) ){
							result = NASLString( "nicht erfüllt" );
							desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-\nServer installiert ist. Allerdings wurde die Datei \n\"/etc/cups/cupsd.conf\" nicht gefunden. Demnach kann das System\nnicht entsprechend Massnahme 5.145 konfiguriert sein." );
						}
						else {
							if( ContainsString( "empty", cupsd ) ){
								result = NASLString( "nicht erfüllt" );
								desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-\nServer installiert ist. Allerdings ist die Datei\n\"/etc/cups/cupsd.conf\" leer. Demnach kann das System nicht\nentsprechend Massnahme 5.145 konfiguriert sein." );
							}
							else {
								if( ContainsString( "none", Listen ) || ContainsString( "none", Browsing ) || ContainsString( "none", LogLevel ) || ContainsString( "none", PreserveJobs ) || ContainsString( "none", AdminResult ) || ContainsString( "none", DefaultAuthType ) ){
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Beim Testen des Systems wurden in der Datei\n\"/etc/cups/cupsd.conf\" folgende Einträge nicht gefunden:\n" );
									if(ContainsString( "none", Listen )){
										desc += NASLString( "Listen, " );
									}
									if(ContainsString( "none", Browsing )){
										desc += NASLString( "Browsing, " );
									}
									if(ContainsString( "none", LogLevel )){
										desc += NASLString( "LogLevel, " );
									}
									if(ContainsString( "none", PreserveJobs )){
										desc += NASLString( "PreserveJobs, " );
									}
									if(ContainsString( "none", DefaultAuthType )){
										desc += NASLString( "DefaultAuthType, " );
									}
									if(ContainsString( "none", AdminResult )){
										desc += NASLString( "<Location /admin>, " );
									}
								}
								else {
									if(!ContainsString( "none", Listen ) && !ContainsString( "none", Browsing ) && !ContainsString( "none", LogLevel ) && !ContainsString( "none", PreserveJobs ) && !ContainsString( "none", AdminResult ) && !ContainsString( "none", DefaultAuthType )){
										result = NASLString( "unvollständig" );
										desc = NASLString( "\nBitte prüfen Sie, ob die Optionen -Listen-, -Browsing-,\n-LogLevel-, -PreserveJobs- und -<Location /admin>- den\nAnforderungen der Maßnahme 5.145 genügen:\n" + Listen + "\n" + Browsing + "\n" + LogLevel + "\n" + PreserveJobs + "\n" + DefaultAuthType + "\n" + AdminResult + "\n" );
									}
								}
							}
						}
					}
					else {
						if(!ContainsString( "nocupsd", cupsd ) && !ContainsString( "nocupsclient", cupsclient )){
							if( ContainsString( "no cupsd.conf", cupsd ) ){
								result = NASLString( "nicht erfüllt" );
								desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-\nServer installiert ist.\nAllerdings wurde die Datei\n/etc/cups/cupsd.conf nicht gefunden. Demnach kann das System\nnicht entsprechend Massnahme 5.145 konfiguriert sein.\n" );
							}
							else {
								if(ContainsString( "empty", cupsd )){
									result = NASLString( "nicht erfüllt" );
									desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-\nServer installiert ist. Allerdings ist die Datei\n/etc/cups/cupsd.conf leer. Demnach kann das System nicht\nentsprechend Massnahme 5.145 konfiguriert sein.\n" );
								}
							}
							if( ContainsString( "no client.conf", cupsclient ) ){
								result = NASLString( "nicht erfüllt" );
								desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-\nClient installiert ist. Allerdings wurde die Datei\n/etc/cups/client.conf nicht gefunden. Demnach kann das System\nnicht entsprechend Massnahme 5.145 konfiguriert sein." );
							}
							else {
								if( ContainsString( "empty", cupsclient ) ){
									result = NASLString( "nicht erfüllt" );
									desc += NASLString( "Beim Testen des Systems wurde festgestellt, dass der CUPS-Client installiert ist.\nAllerdings ist die Datei /etc/cups/client.conf leer.\nDemnach kann das System nicht entsprechend Massnahme 5.145 konfiguriert sein." );
								}
								else {
									if(!ContainsString( "empty", cupsclient ) && !ContainsString( "no client.conf", cupsclient ) && !ContainsString( "no cupsd.conf", cupsd ) && !ContainsString( "empty", cupsd )){
										if( ContainsString( "none", ServerName ) || ContainsString( "none", Encryption ) || ContainsString( "none", Listen ) || ContainsString( "none", Browsing ) || ContainsString( "none", LogLevel ) || ContainsString( "none", PreserveJobs ) || ContainsString( "none", AdminResult ) || ContainsString( "none", DefaultAuthType ) ){
											result = NASLString( "nicht erfüllt" );
											if(ContainsString( "none", Listen ) || ContainsString( "none", Browsing ) || ContainsString( "none", LogLevel ) || ContainsString( "none", PreserveJobs ) || ContainsString( "none", AdminResult ) || ContainsString( "none", DefaultAuthType )){
												desc = NASLString( "Beim Testen des Systems wurden in der Datei \"/etc/cups/cupsd.conf\" folgende Einträge nicht gefunden:\n" );
											}
											if(ContainsString( "none", Listen )){
												desc += NASLString( "Listen, " );
											}
											if(ContainsString( "none", Browsing )){
												desc += NASLString( "Browsing, " );
											}
											if(ContainsString( "none", LogLevel )){
												desc += NASLString( "LogLevel, " );
											}
											if(ContainsString( "none", PreserveJobs )){
												desc += NASLString( "PreserveJobs, " );
											}
											if(ContainsString( "none", DefaultAuthType )){
												desc += NASLString( "DefaultAuthType, " );
											}
											if(ContainsString( "none", AdminResult )){
												desc += NASLString( "<Location /admin>, " );
											}
											if(ContainsString( "none", ServerName ) || ContainsString( "none", Encryption )){
												desc += NASLString( "\nBeim Testen des Systems wurden in der Datei\n/etc/cups/client.conf folgende Einträge nicht gefunden:\n" );
											}
											if(ContainsString( "none", ServerName )){
												desc += NASLString( "ServerName, " );
											}
											if(ContainsString( "none", Encryption )){
												desc += NASLString( "Encryption, " );
											}
										}
										else {
											if(!ContainsString( "none", ServerName ) && !ContainsString( "none", Encryption ) && !ContainsString( "none", Listen ) && !ContainsString( "none", Browsing ) && !ContainsString( "none", LogLevel ) && !ContainsString( "none", PreserveJobs ) && !ContainsString( "none", AdminResult ) && !ContainsString( "none", DefaultAuthType )){
												if( ContainsString( Encryption, "lways" ) ){
													result = NASLString( "unvollständig" );
													desc = NASLString( "Beim Testen des Systems wurden folgende Einträge in der Datei\n/etc/cups/client.conf, gefunden:\n" + ServerName + "\n" + Encryption + "\n" + "Beim Testen des Systems wurden folgende Einträge in der Datei\n/etc/cups/cupsd.conf, gefunden:\n" + Listen + "\n" + Browsing + "\n" + LogLevel + "\n" + PreserveJobs + "\n" + DefaultAuthType + "\n" + AdminResult + "\nBitte prüfen Sie, ob die Optionen -ServerName-, -Listen-,\n-Browsing-, -LogLevel-, -PreserveJobs- und -<Location /admin>-\nden Anforderungen der Maßnahme 5.145 genügen." );
												}
												else {
													result = NASLString( "nicht erfüllt" );
													desc = NASLString( "Beim Testen des Systems wurden folgende Einträge in der Datei\n/etc/cups/client.conf, gefunden:\n" + ServerName + "\n" + Encryption + "\nDie Option -Encryption- sollte auf -Always- gesetzt sein!\nBeim Testen des Systems wurden folgende Einträge in der Datei\n/etc/cups/cupsd.conf, gefunden:\n" + Listen + "\n" + Browsing + "\n" + LogLevel + "\n" + PreserveJobs + "\n" + DefaultAuthType + "\n" + AdminResult + "\nBitte prüfen Sie, ob die Optionen -ServerName-, -Listen-,\n-Browsing-, -LogLevel-, -PreserveJobs- und -<Location /admin>-\nden Anforderungen der Maßnahme 5.145 genügen." );
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
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M5_145/result", value: result );
set_kb_item( name: "GSHB/M5_145/desc", value: desc );
set_kb_item( name: "GSHB/M5_145/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_145" );
}
exit( 0 );

