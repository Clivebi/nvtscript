if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105379" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-05T11:52:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-05 11:52:26 +0000 (Fri, 05 Mar 2021)" );
	script_tag( name: "creation_date", value: "2015-09-21 13:29:25 +0200 (Mon, 21 Sep 2015)" );
	script_name( "Cisco Catalyst 4500 Detection (SNMP)" );
	script_tag( name: "summary", value: "This VT has been replaced by VT 'Cisco IOS XE Detection (SNMP)' (OID: 1.3.6.1.4.1.25623.1.0.144919).

  This script performs SNMP based detection of Cisco Catalyst 4500." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

