if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108765" );
	script_version( "2020-08-25T06:01:08+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:01:08 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-06-02 05:50:19 +0000 (Tue, 02 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Detection of Linux Kernel mitigation status for hardware vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/uname" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html" );
	script_tag( name: "summary", value: "Checks the Linux Kernel mitigation status for hardware (CPU) vulnerabilities." );
	script_tag( name: "qod", value: "80" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
uname = get_kb_item( "ssh/login/uname" );
if(!uname || !eregmatch( string: uname, pattern: "^Linux ", icase: FALSE )){
	exit( 0 );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
path = "/sys/devices/system/cpu/vulnerabilities/";
res = ssh_cmd( socket: sock, cmd: "ls -d " + path + "*", return_errors: TRUE, return_linux_errors_only: TRUE );
res = chomp( res );
if(!res || !strlen( res )){
	ssh_close_connection();
	exit( 0 );
}
if(IsMatchRegexp( res, "command not found" )){
	ssh_close_connection();
	log_message( port: 0, data: "Possible Linux system found but mandatory 'ls' command missing. Can't continue. Response: " + res );
	exit( 0 );
}
if(failed = egrep( string: res, pattern: ": (Permission denied|cannot open )", icase: TRUE )){
	ssh_close_connection();
	set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/access_failed", value: TRUE );
	report = "Access to the \"" + path + "\" sysfs interface not possible:\n\n" + chomp( failed );
	log_message( port: 0, data: report );
	exit( 0 );
}
not_found = egrep( string: res, pattern: ": No such file or directory", icase: TRUE );
if(not_found || !egrep( string: res, pattern: "^" + path, icase: FALSE )){
	ssh_close_connection();
	if( not_found ) {
		report = not_found;
	}
	else {
		report = res;
	}
	report = "\"" + path + "\" sysfs interface not available:\n\n" + chomp( report );
	report += "\n\nBased on this it is assumed that no Linux Kernel mitigations are available.";
	set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/sysfs_not_available", value: TRUE );
	set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/sysfs_not_available/report", value: report );
	log_message( port: 0, data: report );
	exit( 0 );
}
known_mitigations = make_list( "itlb_multihit",
	 "l1tf",
	 "mds",
	 "meltdown",
	 "spec_store_bypass",
	 "spectre_v1",
	 "spectre_v2",
	 "srbds",
	 "tsx_async_abort" );
info = make_array();
for known_mitigation in known_mitigations {
	file = path + known_mitigation;
	cmd = "cat " + file;
	res = ssh_cmd( socket: sock, cmd: cmd, return_errors: TRUE, return_linux_errors_only: FALSE );
	res = chomp( res );
	if( IsMatchRegexp( res, ": No such file or directory" ) ){
		res = "sysfs file missing (" + res + ")";
		set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable", value: TRUE );
		set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/" + known_mitigation, value: res );
	}
	else {
		if( IsMatchRegexp( res, "vulnerable" ) ){
			set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable", value: TRUE );
			set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/" + known_mitigation, value: res );
		}
		else {
			if( IsMatchRegexp( res, "Mitigation: " ) ){
				set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/available", value: TRUE );
				set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/available/" + known_mitigation, value: res );
			}
			else {
				if( IsMatchRegexp( res, "Not affected" ) ){
					set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/not_affected", value: TRUE );
					set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/not_affected/" + known_mitigation, value: res );
				}
				else {
					if( IsMatchRegexp( res, ": Permission denied" ) ){
						set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/permission_denied", value: TRUE );
						set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/permission_denied/" + known_mitigation, value: res );
					}
					else {
						set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/unknown", value: TRUE );
						if( !res ){
							res = "Unknown: No answer received to command \"" + cmd + "\"";
							set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/unknown/" + known_mitigation, value: "No answer received" );
						}
						else {
							res = "Unknown: Unrecognized answer received to command \"" + cmd + "\": " + res;
							set_kb_item( name: "ssh/hw_vulns/kernel_mitigations/unknown/" + known_mitigation, value: res );
						}
					}
				}
			}
		}
	}
	info[file] = res;
}
register_host_detail( name: "Detection of Linux Kernel mitigation status for hardware vulnerabilities", value: "cpe:/a:linux:kernel" );
register_host_detail( name: "cpe:/a:linux:kernel", value: "general/tcp" );
register_host_detail( name: "port", value: "general/tcp" );
report = "Linux Kernel mitigation status for hardware vulnerabilities:\n\n";
report += text_format_table( array: info, sep: " | ", columnheader: make_list( "sysfs file checked",
	 "Kernel status (SSH response)" ) );
report += "\n\nNotes on the \"Kernel status / SSH response\" column:";
report += "\n- sysfs file missing: The sysfs interface is available but the sysfs file for this specific vulnerability is missing. This means the kernel doesn\'t know this vulnerability yet and is not providing any mitigation which means the target system is vulnerable.";
report += "\n- Strings including \"Mitigation:\", \"Not affected\" or \"Vulnerable\" are directly reportedby the Linux Kernel.";
report += "\n- All other strings are responses to various SSH commands.";
log_message( port: 0, data: report );
exit( 0 );

