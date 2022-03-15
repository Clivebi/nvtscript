if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94206" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.052: Geräteschutz unter NT-basierten Windows-Systemen" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04052.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_CD-FD-User-only-access.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_require_keys( "WMI/FD_Allocated", "WMI/CD_Allocated" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.052: Geräteschutz unter NT-basierten Windows-Systemen.

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.052: Geräteschutz unter NT-basierten Windows-Systemen\n";
WMIOSLOG = get_kb_item( "WMI/WMI_OS/log" );
cdalloc = get_kb_item( "WMI/CD_Allocated" );
fdalloc = get_kb_item( "WMI/FD_Allocated" );
cdlog = get_kb_item( "WMI/CD_Allocated/log" );
fdlog = get_kb_item( "WMI/FD_Allocated/log" );
gshbm = "GSHB Maßnahme 4.052: ";
if( WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System." ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System läuft Samba, es ist kein\\nMicrosoft Windows System." );
}
else {
	if( ContainsString( "error", cdalloc ) && ContainsString( "error", fdalloc ) ){
		result = NASLString( "Fehler" );
		if(!cdlog){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(cdlog){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + cdlog + "\n" + fdlog );
		}
	}
	else {
		if( ContainsString( "inapplicable", cdalloc ) && ContainsString( "inapplicable", fdalloc ) ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Das System wurde nicht getestet, da es anscheinend\\nkein Windows-System ist." );
		}
		else {
			if( ContainsString( "on", cdalloc ) && ContainsString( "on", fdalloc ) ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "FD- und CD-Zugriff nur für den lokalen\\nBenutzer freigegeben." );
			}
			else {
				if( ContainsString( "off", cdalloc ) && ContainsString( "on", fdalloc ) ){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Nur FD-Zugriff für den lokalen Benutzer freigegeben.\\nCD-Zugriff ist weiterhin über Netzwerk möglich." );
				}
				else {
					if( ContainsString( "on", cdalloc ) && ContainsString( "off", fdalloc ) ){
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "Nur CD-Zugriff für den lokalen Benutzer freigegeben.\\nFD-Zugriff ist weiterhin über Netzwerk möglich." );
					}
					else {
						result = NASLString( "nicht erfüllt" );
						desc = NASLString( "FD- und CD-Zugriff nicht nur für den lokalen\\nBenutzer freigegeben." );
					}
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_052/result", value: result );
set_kb_item( name: "GSHB/M4_052/desc", value: desc );
set_kb_item( name: "GSHB/M4_052/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_052" );
}
exit( 0 );

