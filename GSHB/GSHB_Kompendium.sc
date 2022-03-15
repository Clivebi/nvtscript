if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109040" );
	script_version( "$Revision: 10624 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:18:47 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2018-01-29 10:14:11 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz, Kompendium" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH" );
	script_family( "Compliance" );
	script_add_preference( name: "Berichtformat", type: "radio", value: "Text;Tabellarisch;Text und Tabellarisch" );
	script_mandatory_keys( "GSHB/silence", "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "compliance_tests.sc", "GSHB/GSHB_SYS.1.2.2.sc", "GSHB/GSHB_SYS.1.3.sc", "GSHB/GSHB_SYS.2.2.2.sc", "GSHB/GSHB_SYS.2.2.3.sc", "GSHB/GSHB_SYS.2.3.sc" );
	script_tag( name: "summary", value: "Zusammenfassung von Tests gemäß IT-Grundschutz Kompendium.

Diese Routinen prüfen sämtliche Massnahmen des
IT-Grundschutz Kompendiums des Bundesamts fuer Sicherheit
in der Informationstechnik (BSI) auf den
Zielsystemen soweit die Maßnahmen auf automatisierte
Weise abgeprüft werden können." );
	exit( 0 );
}
require("GSHB/GSHB_mtitle.inc.sc");
require("GSHB/GSHB_depend.inc.sc");
level = get_kb_item( "GSHB/level" );
report = "Prüfergebnisse gemäß IT-Grundschutz Kompendium:\n\n\n";
log = NASLString( "" );
for m in mtitle {
	m = split( buffer: m, sep: "|", keep: FALSE );
	m_num = m[0];
	m_title = m[1];
	m_level = m[2];
	if(( level == "Basis" && m_level == "Standard" ) || ( level == "Basis" && m_level == "Kern" )){
		continue;
	}
	if(level == "Standard" && m_level == "Kern"){
		continue;
	}
	result = get_kb_item( "GSHB/" + m_num + "/result" );
	desc = get_kb_item( "GSHB/" + m_num + "/desc" );
	if(!result){
		if( ContainsString( depend, m_num ) ){
			result = "Diese Vorgabe muss manuell überprüft werden.";
		}
		else {
			result = "Prüfroutine für diese Maßnahme ist nicht verfügbar.";
		}
	}
	if( !desc ){
		if( ContainsString( depend, m_num ) ){
			desc = "Diese Vorgabe muss manuell überprüft werden.";
		}
		else {
			desc = "Prüfroutine für diese Maßnahme ist nicht verfügbar.";
		}
		read_desc = desc;
	}
	else {
		read_desc = ereg_replace( pattern: "\n", replace: "\\n", string: desc );
		read_desc = ereg_replace( pattern: "\\\\n", replace: "\\n                ", string: read_desc );
	}
	report = report + " \n" + m_num + " " + m_title + "\n" + "Ergebnis:       " + result + "\nDetails:        " + read_desc + "\n_______________________________________________________________________________\n";
	if( ContainsString( "error", result ) ) {
		result = "ERR";
	}
	else {
		if( ContainsString( "Fehler", result ) ) {
			result = "ERR";
		}
		else {
			if( ContainsString( "erfüllt", result ) ) {
				result = "OK";
			}
			else {
				if( ContainsString( "erfuellt", result ) ) {
					result = "OK";
				}
				else {
					if( ContainsString( "nicht zutreffend", result ) ) {
						result = "NS";
					}
					else {
						if( ContainsString( "nicht erfuellt", result ) ) {
							result = "FAIL";
						}
						else {
							if( ContainsString( "nicht erfüllt", result ) ) {
								result = "FAIL";
							}
							else {
								if( ContainsString( "unvollstaendig", result ) ) {
									result = "NC";
								}
								else {
									if( ContainsString( "Diese Vorgabe muss manuell überprüft werden.", result ) ) {
										result = "NA";
									}
									else {
										if(ContainsString( "Prüfroutine für diese Maßnahme ist nicht verfügbar.", result )){
											result = "NI";
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
	ip = get_host_ip();
	log_desc = ereg_replace( pattern: "\n", replace: " ", string: desc );
	log_desc = ereg_replace( pattern: "\\\\n", replace: " ", string: log_desc );
	log = log + NASLString( "\"" + ip + "\"|\"" + m_num + "\"|\"" + result + "\"|\"" + log_desc + "\"" ) + "\n";
}
format = script_get_preference( "Berichtformat" );
if(format == "Text" || format == "Text und Tabellarisch"){
	security_message( port: 0, proto: "IT-Grundschutz", data: report );
}
if(format == "Tabellarisch" || format == "Text und Tabellarisch"){
	log_message( port: 0, proto: "IT-Grundschutz-T", data: log );
}
exit( 0 );

