if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103914" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_xref( name: "IAVA", value: "2001-B-0001" );
	script_name( "Check default community names of the SNMP Agent" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "SNMP" );
	script_dependencies( "gb_open_udp_ports.sc", "gb_default_credentials_options.sc" );
	script_require_udp_ports( 161 );
	script_exclude_keys( "default_credentials/disable_brute_force_checks" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20070428232535/http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  login with default communities. Successful logins are storen in the KB." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("list_array_func.inc.sc");
if(get_kb_item( "default_credentials/disable_brute_force_checks" )){
	exit( 0 );
}
port = 161;
if(!get_udp_port_state( port )){
	exit( 0 );
}
communities = make_list( "Cisco router",
	 "EyesOfNetwork",
	 "cable-docsis",
	 "cascade",
	 "comcomcom",
	 "rmonmgmtuicommunity",
	 "ROUTERmate",
	 "tellmeyoursecrets",
	 "SmartScanServer",
	 "wheel",
	 "ConvergedNetwork",
	 "secret c0de",
	 "\"secret c0de\"",
	 "Secret C0de",
	 "\"Secret C0de\"",
	 "common",
	 "FibreChannel",
	 "diag",
	 "manuf",
	 "danger",
	 "xxyyzz",
	 "public",
	 "private",
	 "0",
	 "0392a0",
	 "1234",
	 "2read",
	 "4changes",
	 "ANYCOM",
	 "Admin",
	 "C0de",
	 "CISCO",
	 "CR52401",
	 "IBM",
	 "ILMI",
	 "I$ilonpublic",
	 "Intermec",
	 "NoGaH$@!",
	 "OrigEquipMfr",
	 "PRIVATE",
	 "PUBLIC",
	 "Private",
	 "Public",
	 "SECRET",
	 "SECURITY",
	 "SNMP",
	 "SNMP_trap",
	 "SUN",
	 "SWITCH",
	 "SYSTEM",
	 "Secret",
	 "Security",
	 "s!a@m#n$p%c",
	 "Switch",
	 "System",
	 "TENmanUFactOryPOWER",
	 "TEST",
	 "access",
	 "adm",
	 "admin",
	 "agent",
	 "agent_steal",
	 "all",
	 "all private",
	 "\"all private\"",
	 "all public",
	 "apc",
	 "bintec",
	 "blue",
	 "c",
	 "cable-d",
	 "canon_admin",
	 "cc",
	 "cisco",
	 "community",
	 "core",
	 "debug",
	 "default",
	 "dilbert",
	 "enable",
	 "field",
	 "field-service",
	 "freekevin",
	 "fubar",
	 "guest",
	 "hello",
	 "hp_admin",
	 "ibm",
	 "ilmi",
	 "intermec",
	 "internal",
	 "l2",
	 "l3",
	 "manager",
	 "mngt",
	 "monitor",
	 "netman",
	 "network",
	 "none",
	 "openview",
	 "pass",
	 "password",
	 "pr1v4t3",
	 "proxy",
	 "publ1c",
	 "read",
	 "read-only",
	 "read-write",
	 "readwrite",
	 "red",
	 "regional",
	 "rmon",
	 "rmon_admin",
	 "ro",
	 "root",
	 "router",
	 "rw",
	 "rwa",
	 "san-fran",
	 "sanfran",
	 "scotty",
	 "secret",
	 "security",
	 "seri",
	 "snmp",
	 "snmpd",
	 "snmptrap",
	 "solaris",
	 "sun",
	 "superuser",
	 "switch",
	 "system",
	 "tech",
	 "test",
	 "test2",
	 "tiv0li",
	 "tivoli",
	 "trap",
	 "world",
	 "write",
	 "xyzzy",
	 "yellow",
	 "volition",
	 "MiniAP",
	 "snmp-Trap" );
name = get_host_name();
if(!IsMatchRegexp( name, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" ) && !ContainsString( name, ":" )){
	names[0] = name;
	dot = strstr( name, "." );
	if(dot){
		name = name - dot;
		names[1] = name;
	}
	for name in names {
		if(!in_array( search: name, array: communities )){
			communities = make_list( communities,
				 name );
		}
	}
}
count = 0;
for(i = 0;communities[i];i++){
	community = communities[i];
	SNMP_BASE = 31;
	COMMUNITY_SIZE = strlen( community );
	sz = COMMUNITY_SIZE % 256;
	len = SNMP_BASE + COMMUNITY_SIZE;
	len_hi = len / 256;
	len_lo = len % 256;
	sendata = raw_string( 0x30, 0x82, len_hi, len_lo, 0x02, 0x01, 0x00, 0x04, sz );
	sendata = sendata + community + raw_string( 0xA1, 0x18, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x30, 0x82, 0x00, 0x09, 0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00 );
	dstport = port;
	soc[i] = open_sock_udp( dstport );
	send( socket: soc[i], data: sendata );
	usleep( 10000 );
}
for(j = 0;communities[j];j++){
	result = recv( socket: soc[j], length: 200, timeout: 1 );
	close( soc[j] );
	if(result){
		count++;
		set_kb_item( name: "SNMP/" + port + "/v12c/detected_community", value: communities[j] );
		set_kb_item( name: "SNMP/v12c/detected_community", value: TRUE );
	}
}
if(count > 4){
	set_kb_item( name: "SNMP/" + port + "/v12c/all_communities", value: TRUE );
}
exit( 0 );

