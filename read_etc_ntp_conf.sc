if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150173" );
	script_version( "2021-01-05T15:36:57+0000" );
	script_tag( name: "last_modification", value: "2021-01-05 15:36:57 +0000 (Tue, 05 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-03-18 14:52:27 +0000 (Wed, 18 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read /etc/ntp.conf (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/ntp.conf" );
	script_tag( name: "summary", value: "The ntpd program is an operating system daemon which sets and
maintains the system time of day in synchronism with Internet standard time servers. It is a
complete implementation of the Network Time Protocol (NTP) version 4, but also retains compatibility
with version 3, as defined by RFC-1305, and version 1 and 2, as defined by RFC-1059 and RFC-1119,
respectively. ntpd does most computations in 64-bit floating point arithmetic and does relatively
clumsy 64-bit fixed point operations only when necessary to preserve the ultimate precision, about
232 picoseconds. While the ultimate precision is not achievable with ordinary workstations and
networks of today, it may be required with future gigahertz CPU clocks and gigabit LANs.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
files = make_list( "/etc/ntp.conf",
	 "/etc/sysconfig/ntpd",
	 "/etc/sysconfig/ntp",
	 "/etc/init.d/ntp" );
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux//etc/ntp.conf/ERROR", value: TRUE );
	set_kb_item( name: "Policy/linux//etc/ntp.conf/stat/ERROR", value: TRUE );
	exit( 0 );
}
for file in files {
	policy_linux_stat_file( socket: sock, file: file );
	policy_linux_file_content( socket: sock, file: file );
}
exit( 0 );

