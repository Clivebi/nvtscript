if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96072" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-07 13:23:53 +0200 (Mon, 07 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "List iptables ruleset" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to List List iptables ruleset." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = get_preference( "auth_port_ssh" );
if(!port){
	port = ssh_get_port( default: 22, ignore_unscanned: TRUE );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	error = ssh_get_error();
	if(!error){
		error = "No SSH Port or Connection!";
	}
	log_message( port: port, data: error );
	set_kb_item( name: "GSHB/iptables/ruleset", value: "error" );
	set_kb_item( name: "GSHB/iptables/targets", value: "error" );
	set_kb_item( name: "GSHB/iptables/names", value: "error" );
	set_kb_item( name: "GSHB/iptables/matches", value: "error" );
	set_kb_item( name: "GSHB/iptables/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/iptables/ruleset", value: "windows" );
	set_kb_item( name: "GSHB/iptables/targets", value: "windows" );
	set_kb_item( name: "GSHB/iptables/names", value: "windows" );
	set_kb_item( name: "GSHB/iptables/matches", value: "windows" );
	exit( 0 );
}
uname = ereg_replace( pattern: "\n", replace: "", string: uname );
if( !IsMatchRegexp( uname, "SunOS .*" ) ){
	ruleset = ssh_cmd( socket: sock, cmd: "iptables -L" );
	if( ContainsString( ruleset, "iptables: command not found" ) || ContainsString( ruleset, "Befehl wurde nicht gefunden" ) ) {
		ruleset = "notfound";
	}
	else {
		if( ContainsString( ruleset, "Permission denied (you must be root)" ) ) {
			ruleset = "noperm";
		}
		else {
			if( ContainsString( ruleset, "superuser" ) ) {
				ruleset = "noperm";
			}
			else {
				if(!ruleset){
					ruleset = "notfound";
				}
			}
		}
	}
	if(ruleset == "notfound" || ruleset == "noperm"){
		targets = ssh_cmd( socket: sock, cmd: "LANG=C ls -l /proc/net/ip_tables_targets" );
		names = ssh_cmd( socket: sock, cmd: "LANG=C ls -l /proc/net/ip_tables_names" );
		matches = ssh_cmd( socket: sock, cmd: "LANG=C ls -l /proc/net/ip_tables_matches" );
		if(IsMatchRegexp( targets, ".*No such file or directory.*" )){
			targets = "notfound";
		}
		if(IsMatchRegexp( names, ".*No such file or directory.*" )){
			names = "notfound";
		}
		if(IsMatchRegexp( matches, ".*No such file or directory.*" )){
			matches = "notfound";
		}
		if(!targets){
			targets = "none";
		}
		if(!names){
			names = "none";
		}
		if(!matches){
			matches = "none";
		}
	}
	set_kb_item( name: "GSHB/iptables/ruleset", value: ruleset );
	set_kb_item( name: "GSHB/iptables/targets", value: targets );
	set_kb_item( name: "GSHB/iptables/names", value: names );
	set_kb_item( name: "GSHB/iptables/matches", value: matches );
}
else {
	if(IsMatchRegexp( uname, "SunOS .*" )){
		ipfilter = ssh_cmd( socket: sock, cmd: "LANG=C /usr/sbin/ipf -V" );
		ipfilterstat = ssh_cmd( socket: sock, cmd: "LANG=C /usr/sbin/ipfstat -io" );
		if( IsMatchRegexp( ipfilter, ".*Permission denied.*" ) ) {
			ipfilter = "noperm";
		}
		else {
			if( IsMatchRegexp( ipfilter, ".*not found.*" ) ) {
				ipfilter = "notfound";
			}
			else {
				if(ipfilter){
					Lst = split( buffer: ipfilter, keep: 0 );
					for(i = 0;i < max_index( Lst );i++){
						if( !IsMatchRegexp( Lst[i], "^Running:.*" ) ) {
							continue;
						}
						else {
							if( IsMatchRegexp( Lst[i], "^Running:.no.*" ) ) {
								ipfilters = "off";
							}
							else {
								if( IsMatchRegexp( Lst[i], "^Running:.yes.*" ) ) {
									ipfilters = "on";
								}
								else {
									ipfilters = "error";
								}
							}
						}
					}
				}
			}
		}
		if( IsMatchRegexp( ipfilterstat, ".*Permission denied.*" ) ) {
			ipfilterstat = "noperm";
		}
		else {
			if( IsMatchRegexp( ipfilterstat, ".*not found.*" ) ) {
				ipfilterstat = "notfound";
			}
			else {
				if(ipfilterstat){
					Lst = split( buffer: ipfilterstat, keep: 0 );
					for(i = 0;i < max_index( Lst );i++){
						if(IsMatchRegexp( Lst[i], "^empty list for ipfilter.out.*" )){
							out = "nofilter";
						}
						if(IsMatchRegexp( Lst[i], "^empty list for ipfilter.in.*" )){
							in = "nofilter";
						}
					}
				}
			}
		}
		if(out == "nofilter" && in == "nofilter"){
			ipfilterstat = "nofilter";
		}
		set_kb_item( name: "GSHB/iptables/uname", value: uname );
		set_kb_item( name: "GSHB/iptables/ipfilter", value: ipfilters );
		set_kb_item( name: "GSHB/iptables/ipfilterstat", value: ipfilterstat );
	}
}
exit( 0 );

