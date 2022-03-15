if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104121" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: modbus-discover" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf" );
	script_xref( name: "URL", value: "https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-bristow.pdf" );
	script_xref( name: "URL", value: "http://code.google.com/p/modscan/" );
	script_tag( name: "summary", value: "Enumerates SCADA Modbus slave ids (sids) and collects their device information.

Modbus is one of the popular SCADA protocols. This script does Modbus device information disclosure.
It tries to find legal sids (slave ids) of Modbus devices and to get additional information about
the vendor and firmware. This script is improvement of modscan python utility written by Mark
Bristow.

Information about MODBUS protocol and security issues can be found in the references.

SYNTAX:

aggressive:  - boolean value defines find all or just first sid" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

