if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106156" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-07-29 09:30:37 +0700 (Fri, 29 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Huawei VRP Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of Huawei Versatile Routing Platform (VRP) devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_xref( name: "URL", value: "http://e.huawei.com/en/products/enterprise-networking/switches" );
	exit( 0 );
}
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "Huawei Versatile Routing Platform( Software)?" )){
	mo = eregmatch( pattern: "Quidway (S[0-9]+([A-Z-]+)?)", string: sysdesc );
	if( !isnull( mo[1] ) ) {
		model = mo[1];
	}
	else {
		if( egrep( pattern: "\\(S(12700|2700|5700|6720|BC) V", string: sysdesc ) ){
			mo = eregmatch( pattern: "^([^\r\n]+)", string: sysdesc );
			if( !isnull( mo[1] ) ) {
				model = chomp( mo[1] );
			}
			else {
				exit( 0 );
			}
		}
		else {
			mo = eregmatch( pattern: "(USG[0-9]{4}) V", string: sysdesc );
			if( !isnull( mo[1] ) ) {
				model = mo[1];
			}
			else {
				mo = eregmatch( pattern: "(ATN[0-9-]+)", string: sysdesc );
				if( !isnull( mo[1] ) ) {
					model = mo[1];
				}
				else {
					mo = eregmatch( pattern: "\\(([A-Z0-9-]+) ", string: sysdesc );
					if( !isnull( mo[1] ) ) {
						model = mo[1];
					}
					else {
						mo = eregmatch( pattern: "(Eudemon.+) V[1-9]00R", string: sysdesc );
						if( !isnull( mo[1] ) ) {
							model = mo[1];
						}
						else {
							exit( 0 );
						}
					}
				}
			}
		}
	}
	version = "unknown";
	vers = eregmatch( pattern: "Version [0-9.]+[^\r\n]*(V[0-9A-Z]+)", string: sysdesc );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	patch = eregmatch( pattern: "Patch.*(V[A-Z0-9]+)", string: sysdesc );
	if( !isnull( patch[1] ) ){
		patch_version = patch[1];
	}
	else {
		patch_version = "No patch installed";
	}
	set_kb_item( name: "huawei/vrp/detected", value: TRUE );
	set_kb_item( name: "huawei/vrp/snmp/detected", value: TRUE );
	set_kb_item( name: "huawei/vrp/snmp/port", value: port );
	set_kb_item( name: "huawei/vrp/snmp/" + port + "/model", value: model );
	set_kb_item( name: "huawei/vrp/snmp/" + port + "/version", value: version );
	set_kb_item( name: "huawei/vrp/snmp/" + port + "/patch", value: patch_version );
	set_kb_item( name: "huawei/vrp/snmp/" + port + "/concluded", value: sysdesc );
	exit( 0 );
}
exit( 0 );

