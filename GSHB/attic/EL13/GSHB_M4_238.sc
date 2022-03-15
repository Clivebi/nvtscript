if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94142" );
	script_version( "2020-08-04T13:27:06+0000" );
	script_tag( name: "last_modification", value: "2020-08-04 13:27:06 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-11-20 14:54:11 +0100 (Wed, 20 Nov 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.238: Einsatz eines lokalen Paketfilters (Windows)" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04238.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-deprecated" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.238: Einsatz eines lokalen Paketfilters (Windows).

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94220

  Stand: 13. Ergänzungslieferung (13. EL).

  Hinweis:

  Getestet wird auf die Microsoft Windows Firewall. Für Vista und Windows 7
  auf jegliche Firewall die sich systemkonform installiert." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

