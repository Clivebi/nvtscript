if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801812" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IBM Tivoli Directory Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ldap_detect.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "ldap/detected" );
	script_tag( name: "summary", value: "This script finds the running IBM Tivoli Directory Server version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ldap.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "IBM Tivoli Directory Server Version Detection";
port = ldap_get_port( default: 389 );
req = raw_string( 0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01, 0x0e, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00, 0x00, 0x00, 0x00 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: req );
result = recv( socket: soc, length: 2000 );
close( soc );
if(ContainsString( result, "International Business Machines" ) && ContainsString( result, "ibmdirectoryversion1" )){
	index = stridx( result, "ibmdirectoryversion1" );
	if(index == -1){
		exit( 0 );
	}
	version = substr( result, index + 22, index + 36 );
	len = strlen( version );
	for(i = 0;i < len;i++){
		if(IsMatchRegexp( version[i], "[0-9.]" )){
			tdsVer = tdsVer + version[i];
		}
	}
	if(tdsVer){
		set_kb_item( name: "IBM/TDS/Ver", value: tdsVer );
		log_message( port: port, data: "Tivoli Directory Server version " + tdsVer + " was detected on the host" );
		cpe = build_cpe( value: tdsVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:tivoli_directory_server:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

