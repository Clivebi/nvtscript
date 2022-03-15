if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105525" );
	script_version( "2021-03-19T08:40:35+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 08:40:35 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-01-22 13:42:01 +0100 (Fri, 22 Jan 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Gather Linux Host Information" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc", "os_detection.sc" );
	script_mandatory_keys( "login/SSH/success", "Host/runs_unixoide" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script attempts to gather some information like the 'uptime'
  from a linux host and stores the results in the KB." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
uptime = ssh_cmd( socket: sock, cmd: "cat /proc/uptime" );
if(uptime && IsMatchRegexp( uptime, "^[0-9]+\\.[0-9]+" )){
	now = unixtime();
	ut = split( buffer: uptime, sep: ".", keep: FALSE );
	uptime = int( ut[0] );
	t_now = ( now - uptime );
	register_host_detail( name: "uptime", value: t_now );
	set_kb_item( name: "Host/uptime", value: t_now );
}
uname = get_kb_item( "Host/uname" );
if(uname && ContainsString( uname, "Linux" )){
	un = split( uname );
	for line in un {
		if(IsMatchRegexp( line, "^Linux" )){
			kv = eregmatch( pattern: "^Linux [^ ]+ ([^ ]+) #([0-9])+", string: line );
			if(!isnull( kv[1] )){
				set_kb_item( name: "Host/running_kernel_version", value: kv[1] );
				register_host_detail( name: "Running-Kernel", value: kv[1] );
			}
			if(!isnull( kv[2] )){
				set_kb_item( name: "Host/running_kernel_build_version", value: kv[2] );
			}
			break;
		}
	}
}
close( sock );
exit( 0 );

