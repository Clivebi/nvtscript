if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150252" );
	script_version( "2021-08-24T08:31:17+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 08:31:17 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-07-10 08:07:44 +0000 (Fri, 10 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Read display ospf peer brief command" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Get the current ospf peer brief configuration of the VRP device.
  Please set screen-length of user-interface to 0, otherwise not all configurations
  may returned.

  Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
if(!get_kb_item( "huawei/vrp/detected" )){
	set_kb_item( name: "Policy/vrp/installed/ERROR", value: TRUE );
	exit( 0 );
}
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/vrp/ssh/ERROR", value: TRUE );
	exit( 0 );
}
cmd = "display ospf peer brief";
ret = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE );
if( !ret ){
	set_kb_item( name: "Policy/vrp/ospf/peer/brief/ERROR", value: TRUE );
}
else {
	if( IsMatchRegexp( ret, "^\\s*<[^>]+>\\s*$" ) ){
		set_kb_item( name: "Policy/vrp/ospf/peer/brief/empty", value: TRUE );
	}
	else {
		for line in split( buffer: ret, keep: FALSE ) {
			if(!IsMatchRegexp( line, "^\\s*[0-9]" )){
				continue;
			}
			line_without_whitespaces = ereg_replace( string: line, pattern: "\\s+", replace: "|" );
			line_reg_match = eregmatch( string: line_without_whitespaces, pattern: "(.+)\\|(.+)\\|(.+)\\|(.+)" );
			if(line_reg_match){
				set_kb_item( name: "Policy/vrp/ospf/peer/brief/interface", value: line_reg_match[2] );
				set_kb_item( name: "Policy/vrp/ospf/peer/brief/interface/" + line_reg_match[2] + "/areid", value: line_reg_match[1] );
				set_kb_item( name: "Policy/vrp/ospf/peer/brief/interface/" + line_reg_match[2] + "/neighborid", value: line_reg_match[3] );
				set_kb_item( name: "Policy/vrp/ospf/peer/brief/interface/" + line_reg_match[2] + "/state", value: line_reg_match[4] );
			}
		}
	}
}
exit( 0 );

