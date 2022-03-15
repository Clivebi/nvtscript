if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100288" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "CVS pserver Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH / LSS" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/cvspserver", 2401 );
	script_tag( name: "summary", value: "This script retrieves the version of CVS pserver." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
func scramble( pass ){
	var x, scrambled, c;
	c[33] = 120;
	c[34] = 53;
	c[37] = 109;
	c[38] = 72;
	c[39] = 108;
	c[40] = 70;
	c[41] = 64;
	c[42] = 76;
	c[43] = 67;
	c[44] = 116;
	c[45] = 74;
	c[46] = 68;
	c[47] = 87;
	c[48] = 111;
	c[49] = 52;
	c[50] = 75;
	c[51] = 119;
	c[52] = 49;
	c[53] = 34;
	c[54] = 82;
	c[55] = 81;
	c[56] = 95;
	c[57] = 65;
	c[58] = 112;
	c[59] = 86;
	c[60] = 118;
	c[61] = 110;
	c[62] = 122;
	c[63] = 105;
	c[65] = 57;
	c[66] = 83;
	c[67] = 43;
	c[68] = 46;
	c[69] = 102;
	c[70] = 40;
	c[71] = 89;
	c[72] = 38;
	c[73] = 103;
	c[74] = 45;
	c[75] = 50;
	c[76] = 42;
	c[77] = 123;
	c[78] = 91;
	c[79] = 35;
	c[80] = 125;
	c[81] = 55;
	c[82] = 54;
	c[83] = 66;
	c[84] = 124;
	c[85] = 126;
	c[86] = 59;
	c[87] = 47;
	c[88] = 92;
	c[89] = 71;
	c[90] = 115;
	c[95] = 56;
	c[97] = 121;
	c[98] = 117;
	c[99] = 104;
	c[100] = 101;
	c[101] = 100;
	c[102] = 69;
	c[103] = 73;
	c[104] = 99;
	c[105] = 63;
	c[106] = 94;
	c[107] = 93;
	c[108] = 39;
	c[109] = 37;
	c[110] = 61;
	c[111] = 48;
	c[112] = 58;
	c[113] = 113;
	c[114] = 32;
	c[115] = 90;
	c[116] = 44;
	c[117] = 98;
	c[118] = 60;
	c[119] = 51;
	c[120] = 33;
	c[121] = 97;
	c[122] = 62;
	for(x = 0;x < strlen( pass );x++){
		scrambled += raw_string( c[ord( pass[x] )] );
	}
	return scrambled;
}
port = service_get_port( default: 2401, proto: "cvspserver" );
logins = make_list( "anonymous",
	 "anoncvs" );
passwords = make_list( "",
	 "anoncvs",
	 "anon" );
for dir in make_list( "/var/lib/cvsd/",
	 "/cvs",
	 "/cvsroot",
	 "/home/ncvs",
	 "/usr/local/cvs",
	 "/u/cvs",
	 "/usr/local/cvsroot" ) {
	for login in logins {
		for password in passwords {
			soc = open_sock_tcp( port );
			if(!soc){
				continue;
			}
			req = NASLString( "BEGIN AUTH REQUEST\\n", dir, "\\n", login, "\\n", "A", scramble( password ), "\\n", "END AUTH REQUEST\\n" );
			send( socket: soc, data: req );
			buf = recv_line( socket: soc, length: 4096 );
			if(!ContainsString( buf, "I LOVE YOU" )){
				close( soc );
				continue;
			}
			set_kb_item( name: "cvs/" + port + "/login", value: login );
			set_kb_item( name: "cvs/" + port + "/pass", value: password );
			set_kb_item( name: "cvs/" + port + "/dir", value: dir );
			send( socket: soc, data: NASLString( "Root ", dir, "\\nversion\\n" ) );
			buf = recv_line( socket: soc, length: 4096 );
			close( soc );
			if(egrep( string: buf, pattern: "CVS", icase: TRUE )){
				install = port + "/tcp";
				version = "unknown";
				vers = eregmatch( string: buf, pattern: "([0-9.]+)" );
				if(!isnull( vers[1] )){
					version = vers[1];
				}
				service_register( port: port, proto: "cvspserver" );
				set_kb_item( name: "cvs/" + port + "/version", value: version );
				set_kb_item( name: "cvspserver/detected", value: TRUE );
				register_and_report_cpe( app: "CVS pserver", ver: version, concluded: vers[0], base: "cpe:/a:cvs:cvs:", expr: "^([0-9.]+)", insloc: install, regPort: port );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

