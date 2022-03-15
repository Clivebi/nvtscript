if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113542" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-10-21 14:53:55 +0200 (Mon, 21 Oct 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "tcpdump Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Checks whether tcpdump is installed on the target system
  and if so, tries to detect the installed version." );
	script_xref( name: "URL", value: "https://www.tcpdump.org/" );
	exit( 0 );
}
CPE_tcpdump = "cpe:/a:tcpdump:tcpdump:";
CPE_libpcap = "cpe:/a:tcpdump:libpcap:";
require("host_details.inc.sc");
require("ssh_func.inc.sc");
require("cpe.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/tcpdump$", useregex: TRUE, sock: sock );
for file in paths {
	file = chomp( file );
	if(!file){
		continue;
	}
	tcpdump_ver = ssh_get_bin_version( full_prog_name: file, version_argv: "--version", ver_pattern: "tcpdump version ([0-9.]+)", sock: sock );
	if(!isnull( tcpdump_ver[1] )){
		set_kb_item( name: "tcpdump/detected", value: TRUE );
		register_and_report_cpe( app: "tcpdump", ver: tcpdump_ver[1], concluded: tcpdump_ver[0], base: CPE_tcpdump, expr: "([0-9.]+)", insloc: file, regPort: 0, regService: "ssh-login" );
	}
	libpcap_ver = ssh_get_bin_version( full_prog_name: file, version_argv: "--version", ver_pattern: "libpcap version ([0-9.]+)", sock: sock );
	if(!isnull( libpcap_ver[1] )){
		set_kb_item( name: "libpcap/detected", value: TRUE );
		register_and_report_cpe( app: "libpcap", ver: libpcap_ver[1], concluded: libpcap_ver[0], base: CPE_libpcap, expr: "([0-9.]+)", insloc: file, regPort: 0, regService: "ssh-login" );
	}
}
exit( 0 );

