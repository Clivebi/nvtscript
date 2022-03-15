if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105797" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-07-06 11:05:47 +0200 (Wed, 06 Jul 2016)" );
	script_name( "HP Comware Devices Detect (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of HP Comware Devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(!IsMatchRegexp( sysdesc, "Comware (Platform )?Software" ) || ( !ContainsString( sysdesc, "Hewlett-Packard Development" ) && !ContainsString( sysdesc, "Hewlett Packard Enterprise Development" ) && !ContainsString( sysdesc, "HP Firewall" ) )){
	exit( 0 );
}
set_kb_item( name: "hp/comware_device", value: TRUE );
cpe = "cpe:/a:hp:comware";
if( ContainsString( sysdesc, "HP Comware Platform" ) && !ContainsString( sysdesc, "HP Series Router" ) ){
	version = eregmatch( pattern: "Software Version ([0-9.]+[^, ]+)", string: sysdesc );
	if(!isnull( version[1] )){
		vers = version[1];
		cpe += ":" + vers;
		set_kb_item( name: "hp/comware_device/version", value: vers );
	}
	release = eregmatch( pattern: "Release ([0-9]+[^ ,\r\n]+)", string: sysdesc );
	if(!isnull( release[1] )){
		rls = release[1];
		set_kb_item( name: "hp/comware_device/release", value: rls );
	}
	model = eregmatch( pattern: "HP ([^Comware][a-zA-Z0-9]+(-)?[^\r\n]+( EI)?[^ \r\n]+)", string: sysdesc );
	if(!isnull( model[1] )){
		mod = model[1];
		set_kb_item( name: "hp/comware_device/model", value: mod );
	}
}
else {
	if( ContainsString( sysdesc, "HP Series Router" ) ){
		version = eregmatch( pattern: "Software Version ([0-9.]+[^, ]+),", string: sysdesc );
		if(!isnull( version[1] )){
			vers = version[1];
			cpe += ":" + vers;
			set_kb_item( name: "hp/comware_device/version", value: vers );
		}
		release = eregmatch( pattern: "Release ([0-9]+[^ ,\r\n]+)", string: sysdesc );
		if(!isnull( release[1] )){
			rls = release[1];
			set_kb_item( name: "hp/comware_device/release", value: rls );
		}
		model = eregmatch( pattern: "Series Router ([^ \r\n]+)", string: sysdesc );
		if(!isnull( model[1] )){
			mod = model[1];
			set_kb_item( name: "hp/comware_device/model", value: mod );
		}
	}
	else {
		if(IsMatchRegexp( sysdesc, "HP Comware Software" )){
			version = eregmatch( pattern: "Product Version ([^ .\r\n]+-[^ .\r\n]+)", string: sysdesc );
			if(!isnull( version[1] )){
				parts = split( buffer: version[1], sep: "-", keep: FALSE );
				if(max_index( parts ) == 3){
					if(!isnull( parts[1] )){
						vers = parts[1];
						cpe += ":" + vers;
						set_kb_item( name: "hp/comware_device/version", value: vers );
					}
					if(!isnull( parts[0] )){
						mod = parts[0];
						set_kb_item( name: "hp/comware_device/model", value: mod );
					}
					if(!isnull( parts[2] )){
						rls = parts[2];
						set_kb_item( name: "hp/comware_device/release", value: rls );
					}
				}
			}
		}
	}
}
register_product( cpe: cpe, location: port + "/udp", proto: "udp", service: "snmp", port: port );
report = "The remote host is a HP Comware Device\nCPE: " + cpe + "\n";
if(vers){
	report += "Version:  " + vers + "\n";
}
if(rls){
	report += "Release:  " + rls + "\n";
}
if(mod){
	report += "Model:    " + mod + "\n";
}
report += "Concluded from SNMP sysDescr OID: " + sysdesc + "\n";
log_message( port: port, data: report, proto: "udp" );
exit( 0 );

