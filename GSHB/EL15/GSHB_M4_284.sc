if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94224" );
	script_version( "$Revision: 11531 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-21 20:50:24 +0200 (Fri, 21 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.284: Umgang mit Diensten ab Windows Server 2003" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04284.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_list_Services.sc", "GSHB/GSHB_WMI_get_AdminUsers.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/nonSystemServices", "WMI/LocalWindowsAdminUsers", "WMI/WMI_OSVER", "WMI/WMI_OSNAME" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.284: Umgang mit Diensten ab Windows Server 2003.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.284: Umgang mit Diensten ab Windows Server 2003\n";
gshbm = "IT-Grundschutz M4.284: ";
services = get_kb_item( "WMI/nonSystemServices" );
LocalAdminUsers = get_kb_item( "WMI/LocalWindowsAdminUsers" );
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
log = get_kb_item( "WMI/LocalWindowsAdminUsers/log" );
if(ContainsString( services, "Name|StartName|State" )){
	services = split( buffer: services, sep: "\n", keep: 0 );
}
if(!ContainsString( "None", LocalAdminUsers ) && !ContainsString( "error", LocalAdminUsers )){
	LocalAdminUsers = split( buffer: LocalAdminUsers, sep: "|", keep: 0 );
}
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba,\\nes ist kein Microsoft Windows System." );
}
else {
	if( ContainsString( services, "error" ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( services, "None" ) ){
			result = NASLString( "erfüllt" );
			desc = NASLString( "Auf dem System laufen alle Dienste gemäß Maßnahme\\nM4.284." );
		}
		else {
			if( OSVER != "5.2" || ContainsString( "Microsoft(R) Windows(R) XP Professional x64 Edition", OSNAME ) ){
				result = NASLString( "nicht zutreffend" );
				desc = NASLString( "Das System ist kein Windows 2003 Server." );
			}
			else {
				if(ContainsString( services[0], "Name|StartName|State" )){
					for(i = 1;i < max_index( services );i++){
						if(ContainsString( services[i], "Name|StartName|State" )){
							continue;
						}
						svinf = split( buffer: services[i], sep: "|", keep: 0 );
						if(svinf != NULL){
							svinf[1] = tolower( svinf[1] );
							if( ContainsString( svinf[1], "@" ) || ( !IsMatchRegexp( svinf[1], "[.]\\\\.*" ) && IsMatchRegexp( svinf[1], "[a-zA-Z0-9äÄöÖüÜß-]{2,}\\\\.*" ) ) ){
								result = result + NASLString( "erfüllt " );
								domservices = domservices + "Dienstname: " + svinf[0] + ",\nUseraccount: " + svinf[1] + ", Dienststatus: " + svinf[2] + ";\n";
								domdesc = NASLString( "\nAuf dem System laufen einige Dienste unter Domänen-\naccounts. Bitte prüfen Sie folgende Dienste:\n" );
							}
							else {
								for(u = 0;u < max_index( LocalAdminUsers );u++){
									if( ContainsString( svinf[1], LocalAdminUsers[u] ) ){
										result = result + NASLString( "nicht erfüllt " );
										servicesdesc = servicesdesc + "Dienstname: " + svinf[0] + ",\nUseraccount: " + svinf[1] + ", Dienststatus: " + svinf[2] + ";\n";
									}
									else {
										result = result + NASLString( "erfüllt " );
									}
								}
							}
						}
					}
					if( ContainsString( result, "nicht" ) ) {
						result = NASLString( "nicht erfüllt" );
					}
					else {
						result = NASLString( "erfüllt" );
					}
					if( servicesdesc ) {
						desc = NASLString( "\nFolgende Dienste entsprechen nicht der\nMaßnahme M4.284:\n" ) + servicesdesc + domdesc + domservices;
					}
					else {
						if( domservices ) {
							desc = domdesc + domservices;
						}
						else {
							if(!servicesdesc && !domservices){
								desc = NASLString( "Auf dem System laufen alle Dienste gemäß\\nMaßnahme M4.284" );
							}
						}
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_284/result", value: result );
set_kb_item( name: "GSHB/M4_284/desc", value: desc );
set_kb_item( name: "GSHB/M4_284/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_284" );
}
exit( 0 );

