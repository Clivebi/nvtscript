if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108657" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-10-01 09:34:13 +0000 (Tue, 01 Oct 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "Ubiquiti Networks Device Compromised" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ubnt_discovery_protocol_detect.sc" );
	script_mandatory_keys( "ubnt_discovery_proto/hostname/detected" );
	script_tag( name: "summary", value: "The remote Ubiquiti Networks Device might have been compromised
  by an attacker or a worm." );
	script_tag( name: "insight", value: "Ubiquiti Networks Devices where targeted in 2017 and later by
  attackers or worms. If an attack was successful the hostname exposed via the UBNT Discovery Protocol
  is changed to include the word 'HACKED'." );
	script_tag( name: "impact", value: "The device might be used by an attacker as a jump host to get access to an internal
  network. It also might be part of a botnet." );
	script_tag( name: "vuldetect", value: "Checks the device hostname previously gathered via the UBNT Discovery Protocol." );
	script_tag( name: "solution", value: "A factory reset of the device is required. Afterwards all available updates should
  be applied and a strong password chosen for the device access.

  Please contact the vendor if further steps are required to clean up and protect the device." );
	script_xref( name: "URL", value: "https://community.ui.com/questions/Device-name-HACKED-ROUTER-HELP-SOS-DEFAULT-PASSWORD/96c5bdbe-dca0-4d7b-86e7-721919ac6e59" );
	script_xref( name: "URL", value: "https://ivanivanov.de/blog/30000-ubiquiti-geraete-kompromittiert/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!port = service_get_port( default: 10001, ipproto: "udp", proto: "ubnt_discovery" )){
	exit( 0 );
}
if(!hostname = get_kb_item( "ubnt_discovery_proto/" + port + "/hostname/detected" )){
	exit( 0 );
}
if(hostname == "HACKED" || egrep( string: hostname, pattern: "^HACKED-ROUTER-HELP-SOS", icase: FALSE )){
	report = "The device reports the following hostname via the UBNT Discovery Protocol which indicates ";
	report += "that the device was compromised by an attacker or a worm:\n\n" + hostname;
	security_message( port: port, proto: "udp", data: report );
	exit( 0 );
}
exit( 99 );

