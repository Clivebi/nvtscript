if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.894037" );
	script_version( "2020-08-04T13:27:06+0000" );
	script_tag( name: "last_modification", value: "2020-08-04 13:27:06 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-10 15:20:25 +0200 (Thu, 10 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04037.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_app" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-deprecated" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern.

  ACHTUNG: Dieser Test wird nicht mehr unterst�tzt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94202

  Diese Pr�fung bezieht sich auf die 11. Erg�nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
  Aktualisierung �ndern, allerdings nicht die Kernthematik.

  Hinweis:

  Cisco Ger�te k�nnen nur �ber Telnet getestet werden, da sie SSH blowfish-cbc encryption nicht unterst�tzen." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );
