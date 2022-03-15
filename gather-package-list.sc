if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.50282" );
	script_version( "2021-08-03T15:00:56+0000" );
	script_tag( name: "last_modification", value: "2021-08-03 15:00:56 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-01-17 22:05:49 +0100 (Thu, 17 Jan 2008)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Determine OS and list of installed packages via SSH login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 E-Soft Inc. http://www.securityspace.com & Tim Brown" );
	script_family( "Product detection" );
	script_dependencies( "ssh_authorization.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_tag( name: "summary", value: "This script will, if given a userid/password or
  key to the remote system, login to that system, determine the OS it is running, and for
  supported systems, extract the list of installed packages/rpms." );
	script_tag( name: "insight", value: "The ssh protocol is used to log in. If a specific port is
  configured for the credential, then only this port will be tried. Else any port that offers
  ssh, usually port 22.

  Upon successful login, the command 'uname -a' is issued to find out about the type and version
  of the operating system.

  The result is analysed for various patterns and in several cases additional commands are tried
  to find out more details and to confirm a detection.

  The regular Linux distributions are detected this way as well as other unixoid systems and
  also many Linux-based devices and appliances.

  If the system offers a package database, for example RPM- or DEB-based, this full list of
  installed packages is retrieved for further patch-level checks." );
	script_tag( name: "qod_type", value: "package" );
	script_timeout( 900 );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
SCRIPT_DESC = "Determine OS and list of installed packages via SSH login";
func register_packages( buf ){
	var buf;
	if(isnull( buf )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#register_packages#-#buf" );
		return NULL;
	}
	buf = ereg_replace( string: buf, pattern: " {3,}", replace: "  " );
	set_kb_item( name: "ssh/login/packages", value: buf );
	return TRUE;
}
func register_rpms( buf, custom_key_name ){
	var buf, custom_key_name;
	var rpms_kb_key;
	if(isnull( buf )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#register_rpms#-#buf" );
		return NULL;
	}
	if(ContainsString( buf, "error: cannot open Packages " )){
		set_kb_item( name: "ssh/login/failed_rpm_db_access", value: TRUE );
		set_kb_item( name: "ssh/login/failed_rpm_db_access/reason", value: chomp( buf ) );
		return FALSE;
	}
	rpms_kb_key = "ssh/login/rpms";
	if(custom_key_name){
		rpms_kb_key = custom_key_name;
	}
	set_kb_item( name: rpms_kb_key, value: buf );
	return TRUE;
}
func register_uname( uname ){
	var uname;
	replace_kb_item( name: "ssh/login/uname", value: uname );
	replace_kb_item( name: "Host/uname", value: uname );
}
func create_lsc_os_detection_report( detect_text, no_lsc_support, rpm_access_error ){
	var detect_text, no_lsc_support, rpm_access_error;
	var report;
	if(isnull( detect_text )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#create_lsc_os_detection_report#-#detect_text" );
		detect_text = "N/A (information missing from the detection)";
	}
	report = "We are able to login and detect that you are running " + detect_text;
	if(!ContainsString( detect_text, "\n" )){
		report += ".";
	}
	if(rpm_access_error){
		report += "\n\nERROR: Access to the RPM database failed. Therefore no local security checks applied (missing list of installed packages) ";
		report += "though SSH login provided and works.";
		report += "\n\nResponse to the \"rpm\" command:\n\n" + rpm_access_error;
	}
	if(no_lsc_support){
		report += "\n\nNote: Local Security Checks (LSC) are not available for this OS.";
	}
	return report;
}
port = kb_ssh_transport();
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
uname = ssh_cmd( socket: sock, cmd: "uname -a", return_errors: TRUE, nosu: TRUE, pty: TRUE, timeout: 60, retry: 30 );
if(!uname){
	exit( 0 );
}
if(ContainsString( uname, "Welcome to Viptela CLI" )){
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	set_kb_item( name: "cisco/detected", value: TRUE );
	show_ver = ssh_cmd( socket: sock, cmd: "show system status", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: FALSE, clear_buffer: TRUE );
	if(ContainsString( show_ver, "vedge Operating System Software" )){
		set_kb_item( name: "ssh/login/cisco/vedge/detected", value: TRUE );
		set_kb_item( name: "ssh/login/cisco/vedge/port", value: port );
		set_kb_item( name: "ssh/login/cisco/vedge/" + port + "/show_ver", value: show_ver );
	}
	exit( 0 );
}
if(_uname = eregmatch( string: uname, pattern: "(Kemp LoadMaster [^\r\n]+ Kemp Technologies|Kemp[^\r\n]+LoadMaster Isetup|LoadMaster configuration \\(KEMP\\))", icase: TRUE )){
	set_kb_item( name: "ssh/login/kemp/loadmaster/detected", value: TRUE );
	set_kb_item( name: "ssh/login/kemp/loadmaster/port", value: port );
	set_kb_item( name: "ssh/login/kemp/loadmaster/" + port + "/concluded", value: _uname[1] );
	os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	set_kb_item( name: "ssh/restricted_shell", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(( IsMatchRegexp( uname, "Lights-Out.*Management" ) && ( IsMatchRegexp( uname, "Copyright .+ ServerEngines Corporation" ) || IsMatchRegexp( uname, "Copyright .+ Hewlett-Packard Development Company" ) || ContainsString( uname, "/./-> Invalid command" ) ) ) || ( ContainsString( uname, " logged-in to " ) && ( IsMatchRegexp( uname, "iLO [0-9]" ) || ContainsString( uname, "hpiLO->" ) ) )){
	sysrev = ssh_cmd( socket: sock, cmd: "SYSREV", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: TRUE, timeout: 20, retry: 10 );
	if(sysrev){
		os_register_unknown_banner( banner: "HP iLO response to the \"SYSREV\" command:\n\n" + sysrev, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	set_kb_item( name: "ssh/restricted_shell", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(_uname = egrep( pattern: "Welcome to (the )?TippingPoint Technologies SMS", string: uname )){
	version = ssh_cmd( socket: sock, cmd: "version", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: TRUE, timeout: 20, retry: 10, pattern: "Version:" );
	if(ContainsString( version, "Version:" )){
		set_kb_item( name: "tippingpoint/sms/ssh-login/" + port + "/version_cmd", value: version );
	}
	set_kb_item( name: "tippingpoint/sms/ssh-login/" + port + "/uname", value: chomp( _uname ) );
	set_kb_item( name: "tippingpoint/sms/ssh-login/version_cmd_or_uname", value: TRUE );
	set_kb_item( name: "tippingpoint/sms/ssh-login/port", value: port );
	set_kb_item( name: "ssh/restricted_shell", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(ContainsString( uname, "HyperIP Command Line Interface" )){
	replace_kb_item( name: "ssh/send_extra_cmd", value: "\n" );
	show_version = ssh_cmd( socket: sock, cmd: "showVersion", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: TRUE, timeout: 20, retry: 10, pattern: "Product Version" );
	if(ContainsString( show_version, "Product Version" ) && ContainsString( show_version, "HyperIP" )){
		set_kb_item( name: "hyperip/ssh-login/" + port + "/show_version", value: show_version );
	}
	set_kb_item( name: "hyperip/ssh-login/" + port + "/uname", value: uname );
	set_kb_item( name: "hyperip/ssh-login/show_version_or_uname", value: TRUE );
	set_kb_item( name: "hyperip/ssh-login/port", value: port );
	set_kb_item( name: "ssh/restricted_shell", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(ContainsString( uname, "> % Command not found" )){
	version = ssh_cmd( socket: sock, cmd: "show version", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: TRUE, timeout: 20, retry: 10 );
	if(version && IsMatchRegexp( version, "ZyXEL Communications Corp\\." )){
		set_kb_item( name: "zyxel/device/ssh-login/" + port + "/show_version_cmd", value: version );
		set_kb_item( name: "zyxel/device/ssh-login/show_version_cmd", value: TRUE );
		set_kb_item( name: "zyxel/device/ssh-login/port", value: port );
		set_kb_item( name: "ssh/restricted_shell", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(_uname = eregmatch( string: uname, pattern: "^.+(::\\*?> \nError: \"[^\"]+\" is not a recognized command|>.+not found\\.  Type \'\\?\' for a list of commands)", icase: FALSE )){
	version = ssh_cmd( socket: sock, cmd: "version", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: TRUE, timeout: 20, retry: 10, pattern: "NetApp Release" );
	if(ContainsString( version, "NetApp Release" )){
		set_kb_item( name: "netapp_data_ontap/ssh-login/" + port + "/version_cmd", value: version );
	}
	set_kb_item( name: "netapp_data_ontap/ssh-login/" + port + "/uname", value: chomp( _uname[0] ) );
	set_kb_item( name: "netapp_data_ontap/ssh-login/version_cmd_or_uname", value: TRUE );
	set_kb_item( name: "netapp_data_ontap/ssh-login/port", value: port );
	set_kb_item( name: "ssh/restricted_shell", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(ContainsString( uname, "Another user is logged into the system at this time" ) && ContainsString( uname, "Are you sure you want to continue" )){
	replace_kb_item( name: "ssh/send_extra_cmd", value: "Yes\n" );
	uname = ssh_cmd( socket: sock, cmd: "uname -a", return_errors: TRUE, pty: TRUE, timeout: 20, retry: 10 );
}
if(ContainsString( uname, "Following disconnected ssh sessions are available to resume" )){
	replace_kb_item( name: "ssh/send_extra_cmd", value: "\n" );
	uname = ssh_cmd( socket: sock, cmd: "uname -a", return_errors: TRUE, pty: TRUE, timeout: 20, retry: 10 );
}
if(ContainsString( uname, "Welcome to Data Domain OS" )){
	set_kb_item( name: "emc/data_domain_os/uname", value: uname );
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: "EMC Data Domain OS" ) );
	exit( 0 );
}
if(un = egrep( string: uname, pattern: "Welcome to pfSense", icase: TRUE )){
	_un = split( buffer: un, keep: FALSE );
	if( IsMatchRegexp( _un[0], "pfsense" ) ) {
		set_kb_item( name: "pfsense/uname", value: _un[0] );
	}
	else {
		set_kb_item( name: "pfsense/uname", value: un );
	}
	set_kb_item( name: "pfsense/ssh/port", value: port );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	set_kb_item( name: "ssh/force/nolang_sh", value: TRUE );
	set_kb_item( name: "ssh/force/clear_buffer", value: TRUE );
	shell = eregmatch( string: uname, pattern: "([0-9])+\\) Shell", icase: TRUE );
	if(!isnull( shell[1] )){
		replace_kb_item( name: "ssh/send_extra_cmd", value: shell[1] + "\n" );
	}
	uname = ssh_cmd( socket: sock, cmd: "uname -a", return_errors: TRUE, pty: TRUE, timeout: 20, retry: 10 );
	is_pfsense = TRUE;
}
if(ContainsString( uname, "Welcome to the Greenbone OS" )){
	set_kb_item( name: "greenbone/gos/uname", value: uname );
	set_kb_item( name: "greenbone/gos", value: TRUE );
	uname = ssh_cmd( socket: sock, cmd: "uname -a", return_errors: FALSE, pty: FALSE, timeout: 20, retry: 10 );
	if(ContainsString( uname, "Type 'gos-admin-menu' to start the Greenbone OS Administration tool" )){
		replace_kb_item( name: "ssh/send_extra_cmd", value: "shell\n" );
		uname = ssh_cmd( socket: sock, cmd: "uname -a", return_errors: FALSE, pty: TRUE, timeout: 20, retry: 10 );
	}
}
if(ContainsString( uname, "HyperFlex-Installer" )){
	set_kb_item( name: "ssh/login/cisco/hyperflex_installer/detected", value: TRUE );
	set_kb_item( name: "ssh/login/cisco/hyperflex_installer/port", value: port );
}
if(ContainsString( tolower( uname ), "linux" )){
	un = egrep( pattern: "(Linux[^\r\n]+)", string: uname );
	if(un){
		u = eregmatch( pattern: "(Linux [^ ]+ [^ ]+ #[0-9]+[^ ]* [^\n]+)", string: un );
		if(!isnull( u[1] )){
			register_uname( uname: u[1] );
		}
	}
}
if(ContainsString( uname, "(Cisco Controller)" )){
	exit( 0 );
}
if(get_kb_item( "greenbone/gos" )){
	exit( 0 );
}
if(ContainsString( uname, "restricted: cannot specify" )){
	set_kb_item( name: "ssh/restricted_shell", value: TRUE );
	exit( 0 );
}
if(ContainsString( uname, "TANDBERG Video Communication Server" )){
	set_kb_item( name: "cisco/ssh/vcs", value: TRUE );
	set_kb_item( name: "ssh/send_extra_cmd", value: "\n" );
	exit( 0 );
}
if(ContainsString( uname, "Cyberoam Central Console" )){
	set_kb_item( name: "cyberoam_cc/detected", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	ccc = eregmatch( pattern: "([0-9]+)\\.\\s*CCC Console", string: uname );
	if(!isnull( ccc[1] )){
		version_info = ssh_cmd( socket: sock, cmd: ccc[1] + "\nccc diagnostics show version-info", nosh: TRUE, nosu: TRUE, pty: TRUE, timeout: 60, retry: 20, pattern: "Hot Fix version" );
		if(ContainsString( version_info, "CCC version:" )){
			set_kb_item( name: "cyberoam_cc/version_info", value: version_info );
		}
	}
	exit( 0 );
}
if(ContainsString( uname, "Welcome to the Immediate Insight Management Console" ) || ( ContainsString( uname, "type 'start' to start the server" ) && ContainsString( uname, "'status' checks the current setup" ) )){
	set_kb_item( name: "firemon/immediate_insight/detected", value: TRUE );
	exit( 0 );
}
if(ContainsString( uname, "Error: Unknown: \"/bin/sh\"" )){
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	set_kb_item( name: "enterasys/detected", value: TRUE );
	exit( 0 );
}
if(ContainsString( uname, "Cisco UCS Director Shell Menu" )){
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	v = eregmatch( pattern: "([0-9]+)\\) Show Version", string: uname );
	if(!isnull( v[1] )){
		show_version = ssh_cmd( socket: sock, cmd: v[1], nosh: TRUE, nosu: TRUE, pty: TRUE, timeout: 60, retry: 20, pattern: "Press return to continue", clear_buffer: TRUE );
		if(show_version && ContainsString( show_version, "Version" ) && ContainsString( show_version, "Build" )){
			set_kb_item( name: "cisco_ucs_director/ssh_login/port", value: port );
			set_kb_item( name: "cisco_ucs_director/show_version", value: show_version );
			exit( 0 );
		}
	}
}
if(ContainsString( tolower( uname ), "% invalid command at '^' marker" ) || ContainsString( uname, "No token match at '^' marker" ) || ContainsString( uname, "NX-OS" ) || ContainsString( uname, "Cisco Nexus Operating System" ) || ContainsString( uname, "Line has invalid autocommand" ) || ContainsString( uname, "The command you have entered is available in the IOS.sh" ) || ( ContainsString( uname, "For more information, enable shell, and then enter:" ) && ContainsString( uname, "'man IOS.sh'" ) )){
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	set_kb_item( name: "cisco/detected", value: TRUE );
	set_kb_item( name: "cisco/ssh-login/port", value: port );
	if(ContainsString( uname, "Line has invalid autocommand" )){
		set_kb_item( name: "ssh/cisco/broken_autocommand", value: TRUE );
	}
	exit( 0 );
}
if(ContainsString( uname, "Command Line Interface is starting up" ) || ContainsString( uname, "Invalid command, a dash character must be preceded" )){
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	system = ssh_cmd( socket: sock, cmd: "show tech ccm_service", nosh: TRUE, nosu: TRUE, pty: TRUE, timeout: 60, retry: 50 );
	if(ContainsString( system, "GroupName: CM Services" )){
		set_kb_item( name: "cisco/cucm/show_tech_ccm_service", value: system );
		set_kb_item( name: "cisco/cucm/detected", value: TRUE );
		exit( 0 );
	}
	if(ContainsString( system, "GroupName: IM and Presence Services" )){
		set_kb_item( name: "cisco/cucmim/show_tech_ccm_service", value: system );
		set_kb_item( name: "cisco/cucmim/detected", value: TRUE );
		exit( 0 );
	}
	if(ContainsString( system, "GroupName: Cisco Finesse Services" )){
		set_kb_item( name: "cisco/finesse/show_tech_ccm_service", value: system );
		set_kb_item( name: "cisco/finesse/detected", value: TRUE );
		exit( 0 );
	}
	exit( 0 );
}
if(IsMatchRegexp( uname, "Cisco Prime( Virtual)? Network Analysis Module" )){
	show_ver = ssh_cmd( socket: sock, cmd: "show version", nosh: TRUE, nosu: TRUE, pty: TRUE, timeout: 30, retry: 10, pattern: "Installed patches:" );
	if(ContainsString( show_ver, "NAM application image" )){
		set_kb_item( name: "cisco_nam/show_ver", value: show_ver );
		set_kb_item( name: "cisco_nam/ssh-login/port", value: port );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(ContainsString( uname, "CMC Build" ) && ContainsString( uname, "LEM" ) && ContainsString( uname, "Exit CMC" )){
	set_kb_item( name: "solarwinds_lem/installed", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	sysinfo = ssh_cmd( socket: sock, cmd: "manager\nviewsysinfo", nosh: TRUE, nosu: TRUE, pty: TRUE, timeout: 90, retry: 10, pattern: "/tmp/swi-lem-sysinfo.txt" );
	vers = eregmatch( pattern: "TriGeo manager version is: ([^\r\n]+)", string: sysinfo );
	if(!isnull( vers[1] )){
		set_kb_item( name: "solarwinds_lem/version/ssh", value: vers[1] );
	}
	build = eregmatch( pattern: "TriGeo manager build is: ([^\r\n]+)", string: sysinfo );
	if(!isnull( build[1] )){
		set_kb_item( name: "solarwinds_lem/build/ssh", value: build[1] );
		hotfix = eregmatch( pattern: "hotfix([0-9]+)", string: build[1] );
		if(!isnull( hotfix[1] )){
			set_kb_item( name: "solarwinds_lem/hotfix/ssh", value: hotfix[1] );
		}
	}
	ubuild = eregmatch( pattern: "TriGeo upgrade build is: ([^\r\n]+)", string: sysinfo );
	if(!isnull( ubuild[1] )){
		set_kb_item( name: "solarwinds_lem/ubuild/ssh", value: ubuild[1] );
	}
	cmc = eregmatch( pattern: "CMC version: ([^\r\n]+)", string: sysinfo );
	if(!isnull( cmc[1] )){
		set_kb_item( name: "solarwinds_lem/cmc_version/ssh", value: cmc[1] );
	}
	exit( 0 );
}
if(ContainsString( uname, "Sourcefire Linux OS" )){
	set_kb_item( name: "sourcefire_linux_os/installed", value: TRUE );
	cpe = "cpe:/o:sourcefire:linux_os";
	version = eregmatch( pattern: "Sourcefire Linux OS v([^ ]+)", string: uname );
	if(!isnull( version[1] )){
		cpe += ":" + version[1];
		set_kb_item( name: "sourcefire_linux_os/version", value: version[1] );
	}
	build = eregmatch( pattern: "\\(build ([^)]+)\\)", string: uname );
	if(!isnull( build[1] )){
		set_kb_item( name: "sourcefire_linux_os/build", value: build[1] );
	}
	os_register_and_report( os: "Sourcefire Linux OS", cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	report = "Sourcefire Linux OS";
	if(version[1]){
		report += "\nVersion: " + version[1];
	}
	if(build[1]){
		report += "\nBuild: " + build[1];
	}
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: report ) );
	exit( 0 );
}
if(ContainsString( uname, "Cisco Firepower Management Center" )){
	set_kb_item( name: "cisco_fire_linux_os/detected", value: TRUE );
	set_kb_item( name: "cisco/detected", value: TRUE );
	if(ContainsString( uname, "Cisco Fire Linux OS" )){
		cpe = "cpe:/o:cisco:fire_linux_os";
		version = eregmatch( pattern: "Cisco Fire Linux OS v([^ ]+)", string: uname );
		if(!isnull( version[1] )){
			cpe += ":" + version[1];
			set_kb_item( name: "cisco/fire_linux_os/version", value: version[1] );
		}
		build = eregmatch( pattern: "\\(build ([^)]+)\\)", string: uname );
		if(!isnull( build[1] )){
			set_kb_item( name: "cisco/fire_linux_os/build", value: build[1] );
		}
		os_register_and_report( os: "Cisco Fire Linux OS", cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		report = "Cisco Fire Linux OS";
		if(version[1]){
			report += "\nVersion: " + version[1];
		}
		if(build[1]){
			report += "\nBuild: " + build[1];
		}
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: report ) );
		exit( 0 );
	}
}
if(IsMatchRegexp( uname, "Cisco NGIPS(v)?" ) && ContainsString( uname, "Cisco Fire Linux OS" )){
	if(ContainsString( uname, "Cisco Fire Linux OS" )){
		cpe = "cpe:/o:cisco:fire_linux_os";
		version = eregmatch( pattern: "Cisco Fire Linux OS v([^ ]+)", string: uname );
		if(!isnull( version[1] )){
			cpe += ":" + version[1];
			set_kb_item( name: "cisco/fire_linux_os/version", value: version[1] );
		}
		build = eregmatch( pattern: "\\(build ([^)]+)\\)", string: uname );
		if(!isnull( build[1] )){
			set_kb_item( name: "cisco/fire_linux_os/build", value: build[1] );
		}
		os_register_and_report( os: "Cisco Fire Linux OS", cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		report = "Cisco Fire Linux OS";
		if(version[1]){
			report += "\nVersion: " + version[1];
		}
		if(build[1]){
			report += "\nBuild: " + build[1];
		}
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: report ) );
	}
	set_kb_item( name: "cisco/ngips/uname", value: uname );
	exit( 0 );
}
if(ContainsString( uname, "CLINFR0329  Invalid command" )){
	show_ver = ssh_cmd( socket: sock, cmd: "show version all", nosh: TRUE, nosu: TRUE, return_errors: FALSE, pty: FALSE );
	if(show_ver && ContainsString( show_ver, "Check Point Gaia" )){
		gaia_cpe = "cpe:/o:checkpoint:gaia_os";
		set_kb_item( name: "checkpoint_fw/detected", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		version = eregmatch( pattern: "Product version Check Point Gaia (R[^\r\n]+)", string: show_ver );
		if(!isnull( version[1] )){
			gaia_cpe += ":" + tolower( version[1] );
			set_kb_item( name: "checkpoint_fw/ssh/version", value: version[1] );
		}
		os_register_and_report( os: "Check Point Gaia", cpe: gaia_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		build = eregmatch( pattern: "OS build ([^\r\n]+)", string: show_ver );
		if(!isnull( build[1] )){
			set_kb_item( name: "checkpoint_fw/ssh/build", value: build[1] );
		}
		report = "Check Point Gaia";
		if(version[1]){
			report += "\nVersion: " + version[1];
		}
		if(build[1]){
			report += "\nBuild: " + build[1];
		}
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: report ) );
		exit( 0 );
	}
}
if(ContainsString( uname, "% Unknown command" )){
	show_ver = ssh_cmd( socket: sock, cmd: "show version", return_errors: FALSE, pty: TRUE, nosh: TRUE, nosu: TRUE, timeout: 20, retry: 10, pattern: "NSX Manager" );
	if(show_ver && ContainsString( show_ver, "NSX Manager" )){
		set_kb_item( name: "vmware_nsx/show_ver", value: show_ver );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		set_kb_item( name: "vmware_nsx/detected_by", value: "SSH" );
		exit( 0 );
	}
}
if(ContainsString( uname, "Error: Unrecognized command found at '^' position." ) || ContainsString( uname, "Error: Wrong parameter found at '^' position." )){
	cmd = "display version";
	display_vers = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, nosu: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE );
	if(ContainsString( display_vers, "Huawei Versatile Routing Platform" )){
		display_vers = ereg_replace( string: display_vers, pattern: "\n[^\r\n]+$", replace: "" );
		set_kb_item( name: "huawei/vrp/display_version", value: display_vers );
		set_kb_item( name: "huawei/vrp/ssh/port", value: port );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		set_kb_item( name: "ssh/force/reconnect", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		concluded_command = "'" + cmd + "'";
		cmd = "display patch-information";
		patch_info = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, nosu: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE );
		if(patch_info){
			if(concluded_command){
				concluded_command += ", ";
			}
			concluded_command += "'" + cmd + "'";
			patch_info = ereg_replace( string: patch_info, pattern: "\n[^\r\n]+$", replace: "" );
			set_kb_item( name: "huawei/vrp/patch-information", value: patch_info );
		}
		cmd = "display device";
		display_dev = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, nosu: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE );
		if(display_dev){
			if(concluded_command){
				concluded_command += ", ";
			}
			concluded_command += "'" + cmd + "'";
			display_dev = ereg_replace( string: display_dev, pattern: "\n<[^\r\n]+>$", replace: "" );
			set_kb_item( name: "huawei/vrp/display_device", value: display_dev );
		}
		set_kb_item( name: "huawei/vrp/ssh-login/" + port + "/concluded_command", value: concluded_command );
		exit( 0 );
	}
}
if(ContainsString( uname, "JUNOS" ) && !ContainsString( uname, "Junos Space" )){
	if(ContainsString( uname, "unknown command" )){
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		set_kb_item( name: "junos/cli", value: TRUE );
	}
	set_kb_item( name: "junos/detected", value: TRUE );
	exit( 0 );
}
if(ContainsString( uname, "Wedge Networks" ) && ContainsString( uname, "BeSecure" ) && ContainsString( uname, "To access the management console" )){
	status = ssh_cmd( socket: sock, cmd: "status show", nosh: TRUE, nosu: TRUE );
	if(ContainsString( status, "Scanner" ) && ContainsString( status, "BeSecure" )){
		set_kb_item( name: "wedgeOS/status", value: status );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(ContainsString( uname, "ERROR: \"/\" not recognized" )){
	sv = ssh_cmd( socket: sock, cmd: "show version", nosh: TRUE, nosu: TRUE, pty: TRUE, pattern: "F5 Networks LROS Version" );
	if(ContainsString( sv, "F5 Networks LROS Version" )){
		set_kb_item( name: "f5/LROS/show_version", value: sv );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(ContainsString( uname, "ERROR: No such command" )){
	system = ssh_cmd( socket: sock, cmd: "show ns version", nosh: TRUE, nosu: TRUE );
	if(ContainsString( system, "NetScaler" )){
		set_kb_item( name: "citrix_netscaler/system", value: system );
		set_kb_item( name: "citrix_netscaler/found", value: TRUE );
		set_kb_item( name: "citrix_netscaler/ssh/port", value: port );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		hw = ssh_cmd( socket: sock, cmd: "show ns hardware", nosh: TRUE, nosu: TRUE );
		if(hw){
			set_kb_item( name: "citrix_netscaler/hardware", value: hw );
		}
		features = ssh_cmd( socket: sock, cmd: "show ns feature", nosh: TRUE, nosu: TRUE );
		if(features){
			set_kb_item( name: "citrix_netscaler/features", value: features );
		}
		exit( 0 );
	}
}
if(ContainsString( uname, "-----unknown keyword " )){
	set_kb_item( name: "ScreenOS/detected", value: TRUE );
	exit( 0 );
}
if(ContainsString( uname, "Unknown command:" ) && ContainsString( uname, "IBM Security Network Protection" )){
	set_kb_item( name: "isnp/detected", value: TRUE );
	set_kb_item( name: "ssh/force/pty", value: TRUE );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(ContainsString( uname, "Unknown command: " ) || ContainsString( uname, "Unknown command or missing feature key" )){
	system = ssh_cmd( socket: sock, cmd: "show system info", nosh: TRUE, nosu: TRUE, pty: TRUE, pattern: "model: PA", retry: 8 );
	if(eregmatch( pattern: "model: PA-", string: system ) && ContainsString( system, "family:" )){
		set_kb_item( name: "palo_alto/detected", value: TRUE );
		set_kb_item( name: "palo_alto/ssh/detected", value: TRUE );
		set_kb_item( name: "palo_alto/ssh/port", value: port );
		set_kb_item( name: "palo_alto/ssh/" + port + "/system", value: system );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
	system = ssh_cmd( socket: sock, cmd: "version", nosh: TRUE, nosu: TRUE );
	if(( ContainsString( system, "Cisco" ) || ContainsString( system, "IronPort" ) ) && IsMatchRegexp( system, "Security( Virtual)? Management" )){
		set_kb_item( name: "cisco_csm/detected", value: TRUE );
		set_kb_item( name: "cisco_csm/ssh-login/detected", value: TRUE );
		set_kb_item( name: "cisco_csm/ssh-login/port", value: port );
		set_kb_item( name: "cisco_csm/ssh-login/" + port + "/concluded", value: system );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		version = "unknown";
		model = "unknown";
		vers = eregmatch( pattern: "Version: ([^\r\n]+)", string: system );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		mod = eregmatch( pattern: "Model: ([^\r\n]+)", string: system );
		if(!isnull( mod[1] )){
			model = mod[1];
		}
		set_kb_item( name: "cisco_csm/ssh-login/" + port + "/version", value: version );
		set_kb_item( name: "cisco_csm/ssh-login/" + port + "/model", value: model );
		exit( 0 );
	}
	if(( ContainsString( system, "Cisco" ) || ContainsString( system, "IronPort" ) ) && IsMatchRegexp( system, "Email Security( Virtual)? Appliance" )){
		set_kb_item( name: "cisco_esa/system", value: system );
		set_kb_item( name: "cisco_esa/installed", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		version = eregmatch( pattern: "Version: ([^\r\n]+)", string: system );
		if(!isnull( version[1] )){
			set_kb_item( name: "cisco_esa/version/ssh", value: version[1] );
		}
		model = eregmatch( pattern: "Model: ([^\r\n]+)", string: system );
		if(!isnull( model[1] )){
			set_kb_item( name: "cisco_esa/model/ssh", value: model[1] );
		}
		exit( 0 );
	}
	if(( ContainsString( system, "Cisco" ) || ContainsString( system, "IronPort" ) ) && IsMatchRegexp( system, "Web Security( Virtual)? Appliance" )){
		set_kb_item( name: "cisco_wsa/system", value: system );
		set_kb_item( name: "cisco_wsa/installed", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		version = eregmatch( pattern: "Version: ([^\r\n]+)", string: system );
		if(!isnull( version[1] )){
			set_kb_item( name: "cisco_wsa/version/ssh", value: version[1] );
		}
		model = eregmatch( pattern: "Model: ([^\r\n]+)", string: system );
		if(!isnull( model[1] )){
			set_kb_item( name: "cisco_wsa/model/ssh", value: model[1] );
		}
		exit( 0 );
	}
}
if(( ContainsString( uname, "diagnose" ) || ContainsString( uname, "traceroute6" ) ) && ContainsString( uname, "enable" ) && ContainsString( uname, "exit" ) && ContainsString( uname, "^" )){
	system = ssh_cmd( socket: sock, cmd: "show system version", nosh: TRUE, nosu: TRUE, pty: FALSE );
	if(ContainsString( system, "Operating System" ) && ContainsString( system, "IWSVA" )){
		set_kb_item( name: "IWSVA/system", value: system );
		set_kb_item( name: "IWSVA/ssh-login/port", value: port );
		set_kb_item( name: "IWSVA/cli_is_clish", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
	system = ssh_cmd( socket: sock, cmd: "show module IMSVA version", nosh: TRUE, nosu: TRUE, pty: FALSE );
	if(IsMatchRegexp( system, "IMSVA [0-9.]+-Build_Linux_[0-9]+" )){
		set_kb_item( name: "IMSVA/system", value: system );
		set_kb_item( name: "IMSVA/ssh-login/port", value: port );
		set_kb_item( name: "IMSVA/cli_is_clish", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(ContainsString( uname, "Invalid input detected at" )){
	set_kb_item( name: "cisco/detected", value: TRUE );
	set_kb_item( name: "cisco/ssh-login/port", value: port );
	set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(ContainsString( uname, "% invalid command detected" )){
	show_ver = ssh_cmd( socket: sock, cmd: "show version", nosh: TRUE, nosu: TRUE, pty: TRUE, pattern: "Internal Build", timeout: 60, retry: 20 );
	if(ContainsString( show_ver, "ERROR : Please enter Yes or No" )){
		show_ver = ssh_cmd( socket: sock, cmd: "Yes\nshow version", nosh: TRUE, nosu: TRUE, pty: TRUE, pattern: "build", timeout: 60, retry: 20 );
	}
	if(ContainsString( show_ver, "Cisco ACS VERSION INFORMATION" )){
		set_kb_item( name: "cisco_acs/show_ver", value: show_ver );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		ade_cpe = "cpe:/o:cisco:application_deployment_engine";
		ade_version = eregmatch( pattern: "ADE-OS Build Version: ([0-9.]+)", string: show_ver );
		if(!isnull( ade_version[1] )){
			ade_cpe += ":" + ade_version[1];
		}
		os_register_and_report( os: "Cisco Application Deployment Engine OS", cpe: ade_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( show_ver, "Cisco Identity Services Engine" )){
		set_kb_item( name: "cisco_ise/show_ver", value: show_ver );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		ade_cpe = "cpe:/o:cisco:application_deployment_engine";
		ade_version = eregmatch( pattern: "ADE-OS Build Version: ([0-9.]+)", string: show_ver );
		if(!isnull( ade_version[1] )){
			ade_cpe += ":" + ade_version[1];
		}
		os_register_and_report( os: "Cisco Application Deployment Engine OS", cpe: ade_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( show_ver, "Cisco Prime Collaboration Provisioning" )){
		set_kb_item( name: "cisco_pcp/show_ver", value: show_ver );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		ade_cpe = "cpe:/o:cisco:application_deployment_engine";
		ade_version = eregmatch( pattern: "ADE-OS Build Version: ([0-9.]+)", string: show_ver );
		if(!isnull( ade_version[1] )){
			ade_cpe += ":" + ade_version[1];
		}
		os_register_and_report( os: "Cisco Application Deployment Engine OS", cpe: ade_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( show_ver, "Cisco Prime Collaboration Assurance" )){
		set_kb_item( name: "cisco_pca/show_ver", value: show_ver );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		ade_cpe = "cpe:/o:cisco:application_deployment_engine";
		ade_version = eregmatch( pattern: "ADE-OS Build Version: ([0-9.]+)", string: show_ver );
		if(!isnull( ade_version[1] )){
			ade_cpe += ":" + ade_version[1];
		}
		os_register_and_report( os: "Cisco Application Deployment Engine OS", cpe: ade_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( show_ver, "Cisco Prime Infrastructure" )){
		set_kb_item( name: "cisco_pis/show_ver", value: show_ver );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		ade_cpe = "cpe:/o:cisco:application_deployment_engine";
		ade_version = eregmatch( pattern: "ADE-OS Build Version: ([0-9.]+)", string: show_ver );
		if(!isnull( ade_version[1] )){
			ade_cpe += ":" + ade_version[1];
		}
		os_register_and_report( os: "Cisco Application Deployment Engine OS", cpe: ade_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( show_ver, "Cisco Prime Network Control System" )){
		set_kb_item( name: "cisco_ncs/show_ver", value: show_ver );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		ade_cpe = "cpe:/o:cisco:application_deployment_engine";
		ade_version = eregmatch( pattern: "ADE-OS Build Version: ([0-9.]+)", string: show_ver );
		if(!isnull( ade_version[1] )){
			ade_cpe += ":" + ade_version[1];
		}
		os_register_and_report( os: "Cisco Application Deployment Engine OS", cpe: ade_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	exit( 0 );
}
if(ContainsString( uname, "uname-a" )){
	ssh_reconnect( sock: sock );
	show_ver = ssh_cmd( socket: sock, cmd: "show version", nosh: TRUE, nosu: TRUE, pty: TRUE, pattern: "Cisco", clear_buffer: TRUE );
	if(show_ver){
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		set_kb_item( name: "cisco/detected", value: TRUE );
	}
	exit( 0 );
}
if(ContainsString( uname, ": No such command" )){
	system = ssh_cmd( socket: sock, cmd: "status", nosh: TRUE, nosu: TRUE, pty: TRUE, pattern: "Version:\\s*FAC" );
	if(IsMatchRegexp( system, "Version:\\s*FAC" ) && ContainsString( system, "Architecture" ) && ContainsString( system, "Branch point" )){
		set_kb_item( name: "FortiOS/Authenticator/system", value: system );
		set_kb_item( name: "ssh/force/pty", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		set_kb_item( name: "ssh/login/release", value: "FortiOS" );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		os_register_and_report( os: "Fortinet FortiOS", cpe: "cpe:/o:fortinet:fortios", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
}
if(ContainsString( uname, "Unknown action 0" )){
	system = ssh_cmd( socket: sock, cmd: "get system status", nosh: TRUE, nosu: TRUE );
	if(ContainsString( system, "Forti" )){
		set_kb_item( name: "FortiOS/system_status", value: system );
		set_kb_item( name: "FortiOS/ssh-login/port", value: port );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		set_kb_item( name: "ssh/login/release", value: "FortiOS" );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		os_register_and_report( os: "Fortinet FortiOS", cpe: "cpe:/o:fortinet:fortios", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		f_version = eregmatch( pattern: "Version\\s*:\\s*(Forti[^ ]* )?v([0-9.]+)", string: system );
		if(!isnull( f_version[2] )){
			set_kb_item( name: "forti/FortiOS/version", value: f_version[2] );
		}
		f_build = eregmatch( string: system, pattern: "[-,]+build([^-, ]+)" );
		if(!isnull( f_build[1] )){
			set_kb_item( name: "forti/FortiOS/build", value: f_build[1] );
		}
		f_typ = eregmatch( string: system, pattern: "Platform Full Name\\s*:\\s*(Forti[^- ]+)" );
		if(!isnull( f_typ[1] )){
			set_kb_item( name: "forti/FortiOS/typ", value: f_typ[1] );
		}
		exit( 0 );
	}
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /opt/vmware/etc/appliance-manifest.xml", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/opt/vmware/etc/appliance-manifest.xml: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "<product>vSphere Data Protection [^<]+</product>" )){
	set_kb_item( name: "vmware/vSphere_Data_Protection/rls", value: rls );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/Novell-VA-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/Novell-VA-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "singleWordProductName=Filr" )){
	set_kb_item( name: "filr/ssh/rls", value: rls );
	set_kb_item( name: "filr/ssh/port", value: port );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/vmware/text_top", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/vmware/text_top: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "VMware vRealize Log Insight" )){
	set_kb_item( name: "vmware/vrealize_log_insight/rls", value: rls );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "vmware -v", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "vmware -v: " + rls + "\n\n";
	}
}
if(_rls = egrep( string: rls, pattern: "^VMware ESX", icase: FALSE )){
	set_kb_item( name: "vmware/esxi/ssh-login/" + port + "/version_banner", value: chomp( _rls ) );
	set_kb_item( name: "vmware/esxi/ssh-login/version_banner", value: TRUE );
	set_kb_item( name: "vmware/esxi/ssh-login/port", value: port );
	exit( 0 );
}
if(ContainsString( tolower( uname ), "linux" )){
	mse_status = ssh_cmd( socket: sock, cmd: "cmxctl version", return_errors: FALSE, nosh: TRUE, nosu: TRUE, pty: TRUE );
	if(ContainsString( mse_status, "Build Version" ) && ContainsString( mse_status, "cmx-" ) && ContainsString( mse_status, "Build Time" )){
		set_kb_item( name: "cisco_mse/status", value: mse_status );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
	mse_status = ssh_cmd( socket: sock, cmd: "getserverinfo", return_errors: FALSE, pty: TRUE, timeout: 30, retry: 10, pattern: "Total Elements" );
	if(ContainsString( mse_status, "Product name: Cisco Mobility Service Engine" )){
		set_kb_item( name: "cisco_mse/status", value: mse_status );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/github/enterprise-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/github/enterprise-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "RELEASE_VERSION" ) && ContainsString( rls, "RELEASE_BUILD_ID" )){
	set_kb_item( name: "github/enterprise/rls", value: rls );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/cisco-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/cisco-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "Cisco IPICS Enterprise Linux Server" )){
	set_kb_item( name: "cisco/ipics/detected", value: TRUE );
	os_register_and_report( os: rls, cpe: "cpe:/o:cisco:linux", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: rls ) );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/.qradar_install_version", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/.qradar_install_version: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "^[0-9]\\.[0-9]\\.[0-9]\\.20(1|2)[0-9]+" )){
	rls = chomp( rls );
	set_kb_item( name: "qradar/version", value: rls );
	typ = ssh_cmd( socket: sock, cmd: "cat /etc/.product_name", return_errors: FALSE );
	if(!isnull( typ )){
		set_kb_item( name: "qradar/product_name", value: typ );
	}
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/nitrosecurity-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/nitrosecurity-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "McAfee ETM " )){
	buildinfo = ssh_cmd( socket: sock, cmd: "cat /etc/NitroGuard/.buildinfo", return_errors: FALSE );
	if(ContainsString( buildinfo, "VERSION" ) && ContainsString( buildinfo, "MAINTVER" )){
		set_kb_item( name: "mcafee/etm/buildinfo", value: buildinfo );
		exit( 0 );
	}
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/system-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/system-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "IPFire" )){
	set_kb_item( name: "ipfire/system-release", value: rls );
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: rls ) );
	os_register_and_report( os: rls, cpe: "cpe:/o:ipfire:linux", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( rls, "Amazon Linux AMI release" )){
	set_kb_item( name: "ssh/login/amazon_linux", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\\n'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	log_message( port: port, data: create_lsc_os_detection_report( rpm_access_error: error, detect_text: "Amazon Linux" ) );
	set_kb_item( name: "ssh/login/release", value: "AMAZON" );
	os_register_and_report( os: "Amazon Linux", cpe: "cpe:/o:amazon:linux", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( rls, "EyesOfNetwork release" )){
	set_kb_item( name: "eyesofnetwork/ssh/port", value: port );
	set_kb_item( name: "eyesofnetwork/ssh/" + port + "/concludedFile", value: "/etc/system-release" );
	set_kb_item( name: "eyesofnetwork/rls", value: rls );
	set_kb_item( name: "ssh/login/centos", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	buf = ssh_cmd( socket: sock, cmd: "cat /etc/system-release-cpe", return_errors: FALSE );
	buf = str_replace( string: buf, find: "centos:linux", replace: "centos:centos" );
	os_ver = eregmatch( pattern: "cpe:/o:centos:centos:([0-9])", string: buf );
	if( !isnull( os_ver[1] ) ){
		oskey = "CentOS" + os_ver[1];
		log_message( port: port, data: create_lsc_os_detection_report( rpm_access_error: error, detect_text: "CentOS release " + os_ver[1] ) );
		set_kb_item( name: "ssh/login/release", value: oskey );
		os_register_and_report( os: "CentOS release " + os_ver[1], cpe: buf, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		log_message( port: port, data: create_lsc_os_detection_report( rpm_access_error: error, detect_text: "CentOS" ) );
	}
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/pgp-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/pgp-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "Symantec Encryption Server" )){
	set_kb_item( name: "symantec_encryption_server/installed", value: TRUE );
	set_kb_item( name: "symantec_encryption_server/rls", value: rls );
	mp = ssh_cmd( socket: sock, cmd: "cat /etc/oem-suffix", return_errors: FALSE );
	if(!isnull( mp )){
		set_kb_item( name: "symantec_encryption_server/MP", value: chomp( mp ) );
	}
	oem_release = ssh_cmd( socket: sock, cmd: "cat /etc/oem-release", return_errors: FALSE );
	if(!isnull( oem_release )){
		set_kb_item( name: "symantec_encryption_server/oem-release", value: chomp( oem_release ) );
	}
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /VERSION", return_errors: TRUE );
	if(strlen( rls ) && !IsMatchRegexp( rls, ": not found" ) && !IsMatchRegexp( rls, ": Permission denied" ) && !IsMatchRegexp( rls, ": cannot open " ) && !IsMatchRegexp( rls, "No such file or directory" ) && !IsMatchRegexp( rls, "command not found" )){
		_unknown_os_info += "/VERSION: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "Syntax Error: unexpected argument" )){
	rls = ssh_cmd( socket: sock, cmd: "run util bash -c \"cat /VERSION\"", nosh: TRUE, nosu: TRUE );
	if(ContainsString( rls, "BIG-" ) || ContainsString( rls, "Product: EM" )){
		set_kb_item( name: "f5/shell_is_tmsh", value: TRUE );
		set_kb_item( name: "ssh/no_linux_shell", value: TRUE );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	}
}
if(ContainsString( rls, "BIG-IP" )){
	set_kb_item( name: "f5/big_ip/lsc", value: TRUE );
	set_kb_item( name: "f5/big_ip/VERSION_RAW", value: rls );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(ContainsString( rls, "BIG-IQ" )){
	set_kb_item( name: "f5/big_iq/lsc", value: TRUE );
	set_kb_item( name: "f5/big_iq/VERSION_RAW", value: rls );
	set_kb_item( name: "f5/big_iq/ssh-login/port", value: port );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(ContainsString( rls, "Product: EM" ) && ContainsString( rls, "BaseBuild" )){
	set_kb_item( name: "f5/f5_enterprise_manager/lsc", value: TRUE );
	set_kb_item( name: "f5/f5_enterprise_manager/VERSION_RAW", value: rls );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/meg-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/meg-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "^McAfee" )){
	set_kb_item( name: "mcafee/OS", value: TRUE );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/esrs-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/esrs-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( chomp( rls ), "^[0-9]+\\.[0-9]+\\.[0-9]$" )){
	set_kb_item( name: "ems/esrs/rls", value: rls );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/NAS_CFG/config.xml", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/NAS_CFG/config.xml (truncated): " + substr( rls, 0, 300 ) + "\n\n";
	}
}
if(IsMatchRegexp( rls, "<hw_ver>(WD)?MyCloud.*</hw_ver>" )){
	set_kb_item( name: "wd-mycloud/ssh-login/" + port + "/cfg_file", value: rls );
	set_kb_item( name: "wd-mycloud/ssh-login/port", value: port );
	set_kb_item( name: "wd-mycloud/ssh-login/cfg_file", value: TRUE );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "rpm -qf /etc/redhat-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "rpm -qf /etc/redhat-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "oraclelinux-release-" )){
	oskey = "OracleLinux";
	cpe = "cpe:/o:oracle:linux";
	os = "Oracle Linux";
	set_kb_item( name: "ssh/login/oracle_linux", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "oraclelinux-release-([0-9]+)\\.?([0-9]+)?", string: rls, icase: TRUE );
	if( vers[1] ){
		if( vers[2] ){
			version = vers[1] + "." + vers[2];
		}
		else {
			version = vers[1];
		}
		cpe += ":" + version;
		oskey += vers[1];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + version, rpm_access_error: error ) );
		os_register_and_report( os: os, version: version, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/redhat-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/redhat-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "Space release " )){
	set_kb_item( name: "junos/space", value: rls );
	exit( 0 );
}
if(ContainsString( rls, "IWSVA release" )){
	system = ssh_cmd( socket: sock, cmd: "/usr/bin/clish -c \"show system version\"", nosh: TRUE, nosu: TRUE, pty: FALSE );
	if(ContainsString( system, "Operating System" ) && ContainsString( system, "IWSVA" )){
		set_kb_item( name: "IWSVA/ssh-login/port", value: port );
		set_kb_item( name: "IWSVA/system", value: system );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(ContainsString( rls, "IMSVA release" )){
	system = ssh_cmd( socket: sock, cmd: "/usr/bin/clish -c \"show module IMSVA version\"", nosh: TRUE, nosu: TRUE, pty: FALSE );
	if(IsMatchRegexp( system, "IMSVA [0-9.]+-Build_Linux_[0-9]+" )){
		set_kb_item( name: "IMSVA/ssh-login/port", value: port );
		set_kb_item( name: "IMSVA/system", value: system );
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		exit( 0 );
	}
}
if(IsMatchRegexp( rls, "^(XenServer|Citrix Hypervisor) release" )){
	set_kb_item( name: "xenserver/installed", value: TRUE );
	exit( 0 );
}
if(IsMatchRegexp( rls, "^McAfee" )){
	set_kb_item( name: "mcafee/OS", value: TRUE );
	exit( 0 );
}
if(IsMatchRegexp( rls, "red hat linux release" )){
	oskey = "RH";
	cpe = "cpe:/o:redhat:linux";
	set_kb_item( name: "ssh/login/redhat_linux", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "red hat linux release ([0-9.]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1];
		oskey += vers[1];
		os_register_and_report( os: rls, version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		os_register_and_report( os: rls, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: rls, rpm_access_error: error ) );
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "fedora" ) && IsMatchRegexp( rls, "release" )){
	oskey = "FC";
	if( IsMatchRegexp( rls, "fedora core" ) ){
		cpe = "cpe:/o:fedoraproject:fedora_core";
		set_kb_item( name: "ssh/login/fedora_core", value: TRUE );
		os = "Fedora Core";
	}
	else {
		cpe = "cpe:/o:fedoraproject:fedora";
		set_kb_item( name: "ssh/login/fedora", value: TRUE );
		os = "Fedora";
	}
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "fedora( core | )release ([0-9]+)", string: rls, icase: TRUE );
	if( vers[2] ){
		cpe += ":" + vers[2];
		oskey += vers[2];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " release " + vers[2], rpm_access_error: error ) );
		os_register_and_report( os: os, version: vers[2], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "red hat enterprise linux.*release" )){
	oskey = "RHENT_";
	cpe = "cpe:/o:redhat:enterprise_linux";
	set_kb_item( name: "ssh/login/rhel", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "red hat enterprise linux.*release (2\\.1|[0-9]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1];
		oskey += vers[1];
		os_register_and_report( os: rls, version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		os_register_and_report( os: rls, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: rls, rpm_access_error: error ) );
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "mandriva" ) || IsMatchRegexp( rls, "mandrake" )){
	oskey = "MNDK_";
	if( IsMatchRegexp( rls, "mandriva linux enterprise server" ) ){
		cpe = "cpe:/o:mandriva:enterprise_server";
		os = "Mandriva Linux Enterprise Server";
	}
	else {
		if( IsMatchRegexp( rls, "mandriva" ) ){
			cpe = "cpe:/o:mandriva:linux";
			os = "Mandriva Linux";
		}
		else {
			cpe = "cpe:/o:mandrakesoft:mandrake_linux";
			os = "Mandrake Linux";
		}
	}
	set_kb_item( name: "ssh/login/mandriva_mandrake_linux", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "mandr(iva|ake).*inux ?(enterprise server)? release ([0-9.]+)", string: rls, icase: TRUE );
	if( vers[3] ){
		cpe += ":" + vers[3];
		if( vers[2] ){
			oskey += "mes" + vers[3];
		}
		else {
			oskey += vers[3];
		}
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " release " + vers[3], rpm_access_error: error ) );
		os_register_and_report( os: os, version: vers[3], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
		if(vers[2] && vers[3] == "5.0"){
			os_register_and_report( os: os, version: "5", cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
		}
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "mageia release" )){
	oskey = "MAGEIA";
	cpe = "cpe:/o:mageia:linux";
	os = "Mageia";
	set_kb_item( name: "ssh/login/mageia_linux", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "mageia release ([0-9.]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1];
		oskey += vers[1];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " release " + vers[1], rpm_access_error: error ) );
		os_register_and_report( os: os, version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "centos( linux)? release" )){
	buf = ssh_cmd( socket: sock, cmd: "/opt/infra/sysmgr/version.sh" );
	if(ContainsString( buf, "Cisco UCS Director Platform" )){
		set_kb_item( name: "cisco_ucs_director/ssh_login/port", value: port );
		set_kb_item( name: "cisco_ucs_director/show_version", value: buf );
		exit( 0 );
	}
}
if(IsMatchRegexp( rls, "centos( linux)? release" )){
	oskey = "CentOS";
	cpe = "cpe:/o:centos:centos";
	os = "CentOS";
	set_kb_item( name: "ssh/login/centos", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "centos( linux)? release ([0-9]+)", string: rls, icase: TRUE );
	if( vers[2] ){
		cpe += ":" + vers[2];
		oskey += vers[2];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " release " + vers[2], rpm_access_error: error ) );
		os_register_and_report( os: os, version: vers[2], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/issue", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/issue: " + rls + "\n\n";
	}
}
match = eregmatch( pattern: "^Univention (Managed Client|Mobile Client|DC Master|DC Backup|DC Slave|Memberserver|Corporate Server) ([2][.][0-4])-[0-9]+-[0-9]+", string: rls );
if(!isnull( match )){
	buf = ssh_cmd( socket: sock, cmd: "COLUMNS=600 dpkg -l" );
	if(!isnull( buf )){
		register_packages( buf: buf );
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: match[0] ) );
		set_kb_item( name: "ssh/login/release", value: "UCS" + match[2] );
		os_register_and_report( os: "Univention Corporate Server", version: match[2], cpe: "cpe:/o:univention:univention_corporate_server", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
}
if(ContainsString( rls, "OpenVPN Access Server Appliance" )){
	set_kb_item( name: "ssh/login/openvpn_as/etc_issue", value: rls );
	set_kb_item( name: "openvpn/ssh-login/port", value: port );
}
if(IsMatchRegexp( rls, "^neco_v[0-9.]+" )){
	set_kb_item( name: "ssh/login/flir/neco_platform/" + port + "/etc_issue", value: chomp( rls ) );
	set_kb_item( name: "ssh/login/flir/neco_platform/port", value: port );
	set_kb_item( name: "ssh/login/flir/neco_platform/detected", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/lsb-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/lsb-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "distrib_id=ubuntu" ) && IsMatchRegexp( rls, "distrib_release=" )){
	os = "Ubuntu";
	oskey = "UBUNTU";
	cpe = "cpe:/o:canonical:ubuntu_linux";
	set_kb_item( name: "ssh/login/ubuntu_linux", value: TRUE );
	vers = eregmatch( pattern: "distrib_release=([0-9]+)\\.([0-9]+)\\.?([0-9]+)?", string: rls, icase: TRUE );
	if( vers[1] && vers[2] ){
		if( IsMatchRegexp( vers[1], "^[0-9]+" ) && version_is_greater_equal( version: vers[1], test_version: "19" ) ) {
			buf = ssh_cmd( socket: sock, cmd: "dpkg --no-pager -l" );
		}
		else {
			buf = ssh_cmd( socket: sock, cmd: "COLUMNS=600 dpkg -l" );
		}
		if(buf){
			register_packages( buf: buf );
		}
		if( vers[3] ) {
			version = vers[1] + "." + vers[2] + "." + vers[3];
		}
		else {
			version = vers[1] + "." + vers[2];
		}
		if( vers[1] % 2 == 0 && IsMatchRegexp( vers[2], "0[46]" ) ){
			lts = " LTS";
			oskey += version + lts;
			cpe += ":" + version + ":-:lts";
		}
		else {
			oskey += version;
			cpe += ":" + version;
		}
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " " + version + lts ) );
		os_register_and_report( os: os, version: version + lts, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "DISTRIB_ID=(\"|\')?Univention(\"|\')?" )){
	ucs_release = eregmatch( string: rls, pattern: "DISTRIB_RELEASE=\"([1-9][0-9]*[.][0-9]+)-([0-9]+) errata([0-9]+)[^\"]*\"" );
	if(!isnull( ucs_release[1] )){
		set_kb_item( name: "ucs/version", value: ucs_release[1] );
	}
	if(!isnull( ucs_release[2] )){
		set_kb_item( name: "ucs/patch", value: ucs_release[2] );
	}
	if(!isnull( ucs_release[3] )){
		set_kb_item( name: "ucs/errata", value: ucs_release[3] );
	}
	ucs_description = eregmatch( string: rls, pattern: "DISTRIB_DESCRIPTION=\"([^\"]*)\"" );
	buf = ssh_cmd( socket: sock, cmd: "COLUMNS=600 dpkg -l" );
	if(buf){
		register_packages( buf: buf );
	}
	if( !isnull( ucs_release ) && !isnull( ucs_description ) ){
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: ucs_description[1] ) );
		set_kb_item( name: "ssh/login/release", value: "UCS" + ucs_release[1] );
		os_register_and_report( os: ucs_description[1], version: ucs_release[1], cpe: "cpe:/o:univention:univention_corporate_server", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_unknown_banner( banner: "Unknown Univention release.\n\ncat /etc/lsb-release:\n\n" + rls, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/conectiva-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/conectiva-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "conectiva linux" )){
	oskey = "CL";
	cpe = "cpe:/o:conectiva:linux";
	os = "Conectiva Linux";
	set_kb_item( name: "ssh/login/conectiva", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "conectiva linux ([0-9.]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1];
		oskey += vers[1];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " " + vers[1], rpm_access_error: error ) );
		os_register_and_report( os: os, version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/turbolinux-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/turbolinux-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "turbolinux (workstation|server|desktop)" )){
	if( IsMatchRegexp( rls, "workstation" ) ){
		oskey = "TLWS";
		cpe = "cpe:/o:turbolinux:turbolinux_workstation";
		os = "Turbolinux Workstation";
	}
	else {
		if( IsMatchRegexp( rls, "server" ) ){
			oskey = "TLS";
			cpe = "cpe:/o:turbolinux:turbolinux_server";
			os = "Turbolinux Server";
		}
		else {
			oskey = "TLDT";
			cpe = "cpe:/o:turbolinux:turbolinux_desktop";
			os = "Turbolinux Desktop";
		}
	}
	set_kb_item( name: "ssh/login/turbolinux", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "turbolinux.*([0-9.]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1];
		oskey += vers[1];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " " + vers[1], rpm_access_error: error, no_lsc_support: TRUE ) );
		os_register_and_report( os: os, version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error, no_lsc_support: TRUE ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "turbolinux" )){
	log_message( port: port, data: "We have detected you are running a version of Turbolinux currently not supported. Please report the following banner: " + rls );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/debian_version", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/debian_version: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "^[0-9]+[0-9.]+" ) || IsMatchRegexp( rls, "buster/sid" ) || IsMatchRegexp( rls, "bullseye/sid" )){
	rls = chomp( rls );
	cpe = "cpe:/o:debian:debian_linux";
	oskey = "DEB";
	set_kb_item( name: "ssh/login/debian_linux", value: TRUE );
	if( ( IsMatchRegexp( rls, "^[0-9]+[0-9.]+" ) && version_is_greater_equal( version: rls, test_version: "10" ) ) || IsMatchRegexp( rls, "buster/sid" ) || IsMatchRegexp( rls, "bullseye/sid" ) ){
		buf = ssh_cmd( socket: sock, cmd: "dpkg --no-pager -l" );
	}
	else {
		buf = ssh_cmd( socket: sock, cmd: "COLUMNS=600 dpkg -l" );
	}
	if(buf){
		register_packages( buf: buf );
		if(concl = egrep( string: buf, pattern: "^ii.+(pve-manager|Proxmox Virtual Environment Management Tools)", icase: FALSE )){
			concl = chomp( concl );
			concl = ereg_replace( string: concl, pattern: " {3,}", replace: "  " );
			set_kb_item( name: "ssh/login/proxmox/ve/detected", value: TRUE );
			set_kb_item( name: "ssh/login/proxmox/ve/port", value: port );
			set_kb_item( name: "ssh/login/proxmox/ve/" + port + "/concluded", value: concl );
		}
	}
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: "Debian GNU/Linux " + rls ) );
	vers = eregmatch( pattern: "^([0-9]+)([0-9.]+)", string: rls );
	if(vers[1]){
		cpe += ":" + vers[1];
		oskey += vers[1];
	}
	if(vers[2]){
		cpe += vers[2];
		if(IsMatchRegexp( vers[1], "^[1-3]$" )){
			oskey += vers[2];
		}
	}
	if(!vers){
		if( IsMatchRegexp( rls, "buster/sid" ) ){
			cpe += ":10.0";
			oskey += "10";
		}
		else {
			if(IsMatchRegexp( rls, "bullseye/sid" )){
				cpe += ":11.0";
				oskey += "11";
			}
		}
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	os_register_and_report( os: "Debian GNU/Linux", version: rls, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/slackware-version", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/slackware-version: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "slackware" )){
	oskey = "SLK";
	cpe = "cpe:/o:slackware:slackware_linux";
	set_kb_item( name: "ssh/login/slackware_linux", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "ls /var/log/packages" );
	if(buf){
		set_kb_item( name: "ssh/login/slackpack", value: buf );
	}
	vers = eregmatch( pattern: "slackware ([0-9.]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1];
		oskey += vers[1];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: "Slackware " + vers[1] ) );
		os_register_and_report( os: "Slackware", version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: "Slackware" ) );
		os_register_and_report( os: "Slackware", cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/os-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/os-release: " + rls + "\n\n";
		os_rls = rls;
	}
	if(!rls){
		rls = ssh_cmd( socket: sock, cmd: "cat /usr/lib/os-release", return_errors: FALSE );
		if(strlen( rls )){
			_unknown_os_info += "/usr/lib/os-release: " + rls + "\n\n";
			os_rls = rls;
		}
	}
}
if(IsMatchRegexp( rls, "(open)?suse( leap| linux)?" ) && !IsMatchRegexp( rls, "enterprise" )){
	if( IsMatchRegexp( rls, "opensuse leap" ) ){
		oskey = "openSUSELeap";
		cpe = "cpe:/o:opensuse:leap";
		os = "openSUSE Leap";
	}
	else {
		if( IsMatchRegexp( rls, "opensuse" ) ){
			oskey = "openSUSE";
			cpe = "cpe:/o:novell:opensuse";
			os = "openSUSE";
		}
		else {
			oskey = "SUSE";
			cpe = "cpe:/o:novell:suse_linux";
			os = "SuSE Linux";
		}
	}
	set_kb_item( name: "ssh/login/suse", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "(open)?suse (leap |linux )?([0-9.]+)", string: rls, icase: TRUE );
	if( vers[3] ){
		cpe += ":" + vers[3];
		oskey += vers[3];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " " + vers[3], rpm_access_error: error ) );
		os_register_and_report( os: os, version: vers[3], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(ContainsString( rls, "NAME=\"Arch Linux\"" )){
	set_kb_item( name: "ssh/login/arch_linux", value: TRUE );
	log_message( port: port, data: create_lsc_os_detection_report( no_lsc_support: TRUE, detect_text: "Arch Linux" ) );
	set_kb_item( name: "ssh/login/release", value: "ArchLinux" );
	os_register_and_report( os: "Arch Linux", cpe: "cpe:/o:archlinux:arch_linux", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( rls, "NAME=NixOS" ) || ContainsString( rls, "ID=nixos" )){
	set_kb_item( name: "ssh/login/nixos", value: TRUE );
	version = eregmatch( pattern: "VERSION_ID=\"([^\"]+)\"", string: rls );
	if( version[1] ){
		log_message( port: port, data: create_lsc_os_detection_report( no_lsc_support: TRUE, detect_text: "NixOS " + version[1] ) );
		os_register_and_report( os: "NixOS", version: version[1], cpe: "cpe:/o:nixos_project:nixos", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( no_lsc_support: TRUE, detect_text: "an unknown NixOS release" ) );
		os_register_and_report( os: "NixOS", cpe: "cpe:/o:nixos_project:nixos", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		os_register_unknown_banner( banner: "Unknown NixOS release.\n\ncat /etc/os-release: " + rls, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	exit( 0 );
}
if(ContainsString( rls, "NAME=\"VMware Photon OS\"" )){
	set_kb_item( name: "ssh/login/photonos", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "cat /etc/photon-release", return_errors: FALSE, force_reconnect: TRUE );
	version = eregmatch( pattern: "VMware Photon OS ([0-9.]+)", string: buf );
	if( !isnull( version[1] ) ){
		build = "unknown";
		bld = eregmatch( pattern: "PHOTON_BUILD_NUMBER=([0-9]+)", string: buf );
		if(!isnull( bld[1] )){
			build = bld[1];
			set_kb_item( name: "ssh/login/photonos/build", value: build );
		}
		log_message( port: port, data: create_lsc_os_detection_report( no_lsc_support: TRUE, detect_text: "VMware Photon OS " + version[1] + " Build: " + build ) );
		os_register_and_report( os: "VMware Photon OS", version: version[1], cpe: "cpe:/o:vmware:photonos", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( no_lsc_support: TRUE, detect_text: "an unknown VMware Photon OS release" ) );
		os_register_and_report( os: "VMware Photon OS", cpe: "cpe:/o:vmware:photonos", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		os_register_unknown_banner( banner: "Unknown VMware Photon OS release.\n\ncat /etc/photon-release: " + buf, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	exit( 0 );
}
if(IsMatchRegexp( rls, "((ID|NAME|VERSION)=flir|PRETTY_NAME=FLIR Systems platform)" ) && ContainsString( rls, "neco" )){
	set_kb_item( name: "ssh/login/flir/neco_platform/" + port + "/etc_os-release", value: chomp( rls ) );
	set_kb_item( name: "ssh/login/flir/neco_platform/port", value: port );
	set_kb_item( name: "ssh/login/flir/neco_platform/detected", value: TRUE );
	replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/SuSE-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/SuSE-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "suse linux enterprise desktop " ) || IsMatchRegexp( os_rls, "suse linux enterprise desktop " )){
	oskey = "SLED";
	cpe = "cpe:/o:suse:linux_enterprise_desktop";
	os = "SUSE Linux Enterprise Desktop";
	if( !IsMatchRegexp( rls, "suse linux enterprise desktop " ) ){
		rls = os_rls;
		patch = eregmatch( pattern: "SUSE Linux Enterprise Desktop [0-9]+ SP([0-9]+)", string: rls, icase: TRUE );
		if( patch[1] ) {
			patchlevel = patch[1];
		}
		else {
			patchlevel = "0";
		}
	}
	else {
		patch = eregmatch( pattern: "patchlevel = ([0-9]+)", string: rls, icase: TRUE );
		if( patch[1] ) {
			patchlevel = patch[1];
		}
		else {
			patchlevel = "0";
		}
	}
	set_kb_item( name: "ssh/login/suse", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "suse linux enterprise desktop ([0-9]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1] + ":sp" + patchlevel;
		oskey += vers[1] + ".0SP" + patchlevel;
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " " + vers[1] + " SP" + patchlevel, rpm_access_error: error ) );
		os_register_and_report( os: os, version: vers[1], patch: "SP" + patchlevel, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(IsMatchRegexp( rls, "suse linux enterprise server " ) || IsMatchRegexp( os_rls, "suse linux enterprise server " )){
	oskey = "SLES";
	cpe = "cpe:/o:suse:linux_enterprise_server";
	os = "SUSE Linux Enterprise Server";
	if( !IsMatchRegexp( rls, "suse linux enterprise server " ) ){
		rls = os_rls;
		patch = eregmatch( pattern: "SUSE Linux Enterprise Server [0-9]+ SP([0-9]+)", string: rls, icase: TRUE );
		if( patch[1] ) {
			patchlevel = patch[1];
		}
		else {
			patchlevel = "0";
		}
	}
	else {
		patch = eregmatch( pattern: "patchlevel = ([0-9]+)", string: rls, icase: TRUE );
		if( patch[1] ) {
			patchlevel = patch[1];
		}
		else {
			patchlevel = "0";
		}
	}
	set_kb_item( name: "ssh/login/suse_sles", value: TRUE );
	set_kb_item( name: "ssh/login/suse", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "suse linux enterprise server ([0-9]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		version = vers[1];
		if( version < "11" || ( version == "11" && patchlevel == "0" ) ){
			oskey += version + ".0";
			cpe += ":" + version;
		}
		else {
			oskey += version + ".0SP" + patchlevel;
			cpe += ":" + version + ":sp" + patchlevel;
		}
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, version: version, patch: "SP" + patchlevel, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(!is_pfsense){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "Endian Firewall " )){
	set_kb_item( name: "endian_firewall/release", value: rls );
	exit( 0 );
}
if(rls = egrep( string: rls, pattern: "OpenIndiana ", icase: FALSE )){
	rls = chomp( rls );
	concl = "/etc/release: " + rls;
	set_kb_item( name: "openindiana/release", value: rls );
	report = "OpenIndiana";
	openi_cpe = "cpe:/o:openindiana:openindiana";
	if( ContainsString( rls, " Development " ) ){
		openi_version = eregmatch( pattern: "OpenIndiana Development oi_([0-9.]+)", string: rls );
		openi_cpe += "_development";
	}
	else {
		if( ContainsString( rls, " Hipster " ) ){
			openi_version = eregmatch( pattern: "OpenIndiana Hipster ([0-9.]+)", string: rls );
			openi_cpe += "_hipster";
		}
		else {
			os_register_unknown_banner( banner: rls, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
			openi_cpe += "_unknown_release";
		}
	}
	if( !isnull( openi_version[1] ) ){
		report += " " + openi_version[1];
		os_register_and_report( os: "OpenIndiana", version: openi_version[1], cpe: openi_cpe, banner_type: "SSH login", banner: concl, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "OpenIndiana", cpe: openi_cpe, banner_type: "SSH login", banner: concl, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	log_message( port: port, data: create_lsc_os_detection_report( no_lsc_support: TRUE, detect_text: report ) );
	is_openindiana = TRUE;
}
if(!is_pfsense && !is_openindiana){
	rls2 = ssh_cmd( socket: sock, cmd: "cat /etc/trustix-release", return_errors: FALSE );
	if(strlen( rls2 )){
		_unknown_os_info += "/etc/trustix-release: " + rls2 + "\n\n";
	}
}
if(IsMatchRegexp( rls, "trustix secure linux release" ) || IsMatchRegexp( rls2, "trustix secure linux release" )){
	oskey = "TSL";
	cpe = "cpe:/o:trustix:secure_linux";
	os = "Trustix";
	set_kb_item( name: "ssh/login/trustix", value: TRUE );
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if(!register_rpms( buf: ";" + buf )){
			error = buf;
		}
	}
	vers = eregmatch( pattern: "trustix secure linux release ([0-9.]+)", string: rls, icase: TRUE );
	if( vers[1] ){
		cpe += ":" + vers[1];
		oskey += vers[1];
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " " + vers[1], rpm_access_error: error, no_lsc_support: TRUE ) );
		os_register_and_report( os: os, version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
	}
	else {
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: os, rpm_access_error: error, no_lsc_support: TRUE ) );
		os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	set_kb_item( name: "ssh/login/release", value: oskey );
	exit( 0 );
}
if(!is_pfsense && !is_openindiana){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/gentoo-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/gentoo-release: " + rls + "\n\n";
	}
}
if(ContainsString( rls, "Gentoo" )){
	set_kb_item( name: "ssh/login/gentoo", value: TRUE );
	set_kb_item( name: "ssh/login/release", value: "GENTOO" );
	buf = ssh_cmd( socket: sock, cmd: "find /var/db/pkg -mindepth 2 -maxdepth 2 -printf \"%P\\n\"" );
	set_kb_item( name: "ssh/login/pkg", value: buf );
	buf = ssh_cmd( socket: sock, cmd: "find /usr/portage/ -wholename '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\\([^/]*\\)/.*/\\([^/]*\\)\\.ebuild$,\\1/\\2,'" );
	if(strlen( buf ) == 0){
		buf = ssh_cmd( socket: sock, cmd: "find /usr/portage/ -path '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\\([^/]*\\)/.*/\\([^/]*\\)\\.ebuild$,\\1/\\2,'" );
	}
	set_kb_item( name: "ssh/login/gentoo_maintained", value: buf );
	log_message( port: port, data: create_lsc_os_detection_report( detect_text: "Gentoo" ) );
	os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(!is_pfsense && !is_openindiana){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/euleros-release", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/euleros-release: " + rls + "\n\n";
	}
}
if(IsMatchRegexp( rls, "EulerOS release" )){
	rls = chomp( rls );
	set_kb_item( name: "ssh/login/euleros", value: TRUE );
	set_kb_item( name: "ssh/login/euleros/port", value: port );
	set_kb_item( name: "ssh/login/euleros/" + port + "/euleros_release", value: rls );
	release_match = eregmatch( pattern: "EulerOS release ([0-9]+\\.[0-9]+)\\s?(\\((SP[0-9]+)(x86_64)?\\))?", string: rls, icase: FALSE );
	if(release_match[1]){
		formatted_os_release = "EulerOS V" + release_match[1];
		if( release_match[3] ){
			formatted_os_release += release_match[3];
		}
		else {
			formatted_os_release += "SP0";
		}
		if(release_match[4]){
			formatted_os_release += "(" + release_match[4] + ")";
		}
		set_kb_item( name: "ssh/login/release_notus", value: formatted_os_release );
	}
	_rls = ssh_cmd( socket: sock, cmd: "cat /etc/uvp-release", return_errors: FALSE );
	if(_rls && ContainsString( _rls, "EulerOS Virtualization" )){
		set_kb_item( name: "ssh/login/euleros/is_uvp", value: TRUE );
		if(ContainsString( _rls, "ARM" )){
			set_kb_item( name: "ssh/login/euleros/is_uvp_arm", value: TRUE );
		}
		set_kb_item( name: "ssh/login/euleros/" + port + "/is_uvp", value: TRUE );
		_rls = chomp( _rls );
		set_kb_item( name: "ssh/login/euleros/" + port + "/uvp_release", value: _rls );
		release_match = eregmatch( pattern: "EulerOS Virtualization ([a-zA-Z0-9 ]+) ([0-9.]+)", string: _rls, icase: FALSE );
		if(release_match[1]){
			formatted_os_release = "EulerOS Virtualization ";
			if(ContainsString( release_match[1], "for ARM 64" )){
				formatted_os_release += "for ARM 64 ";
			}
			if(release_match[2]){
				formatted_os_release += release_match[2];
			}
			set_kb_item( name: "ssh/login/release_notus", value: formatted_os_release );
		}
		rls = _rls + "\n(Base system: " + rls + ")";
	}
	_rls = ssh_cmd( socket: sock, cmd: "cat /etc/uvp_version", return_errors: FALSE );
	if(_rls && ContainsString( _rls, "uvp_version=" )){
		set_kb_item( name: "ssh/login/euleros/is_uvp", value: TRUE );
		if(ContainsString( _rls, "ARM" )){
			set_kb_item( name: "ssh/login/euleros/is_uvp_arm", value: TRUE );
		}
		set_kb_item( name: "ssh/login/euleros/" + port + "/is_uvp", value: TRUE );
		set_kb_item( name: "ssh/login/euleros/" + port + "/uvp_version", value: chomp( _rls ) );
	}
	buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
	if(buf){
		if( !register_rpms( buf: ";" + buf ) ) {
			error = buf;
		}
		else {
			buf = ssh_cmd( socket: sock, cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'" );
			if(buf){
				if(!register_rpms( buf: buf, custom_key_name: "ssh/login/rpms_notus" )){
					error = buf;
				}
			}
		}
	}
	log_message( port: port, data: create_lsc_os_detection_report( rpm_access_error: error, detect_text: rls ) );
	exit( 0 );
}
if(IsMatchRegexp( uname, "hp-ux" )){
	rls = ssh_cmd( socket: sock, cmd: "uname -r" );
	if(IsMatchRegexp( rls, "([0-9.]+)" )){
		oskey = "HPUX";
		cpe = "cpe:/o:hp:hp-ux";
		os = "HP-UX";
		set_kb_item( name: "ssh/login/hp_hp-ux", value: TRUE );
		buf = ssh_cmd( socket: sock, cmd: "swlist -l patch -a supersedes" );
		set_kb_item( name: "ssh/login/hp_pkgsupersedes", value: buf );
		buf = ssh_cmd( socket: sock, cmd: "swlist -a revision -l fileset" );
		set_kb_item( name: "ssh/login/hp_pkgrev", value: buf );
		vers = eregmatch( pattern: "([0-9.]+)", string: rls );
		if( vers[1] ){
			cpe += ":" + vers[1];
			oskey += vers[1];
			log_message( port: port, data: create_lsc_os_detection_report( detect_text: os + " " + vers[1] ) );
			os_register_and_report( os: os, version: vers[1], cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide", full_cpe: TRUE );
		}
		else {
			log_message( port: port, data: create_lsc_os_detection_report( detect_text: os ) );
			os_register_and_report( os: os, cpe: cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		set_kb_item( name: "ssh/login/release", value: oskey );
		exit( 0 );
	}
}
uname = ssh_cmd( socket: sock, cmd: "uname -a" );
if(ContainsString( uname, "FreeBSD" )){
	set_kb_item( name: "ssh/login/freebsd", value: TRUE );
	register_uname( uname: uname );
	found = 0;
	version = eregmatch( pattern: "^[^ ]+ [^ ]+ ([^ ]+)+", string: uname );
	splitup = eregmatch( pattern: "([^-]+)-([^-]+)-p([0-9]+)", string: version[1] );
	if(!isnull( splitup )){
		release = splitup[1];
		patchlevel = splitup[3];
		found = 1;
	}
	if(found == 0){
		splitup = eregmatch( pattern: "([^-]+)-RELEASE", string: version[1] );
		if(!isnull( splitup )){
			release = splitup[1];
			patchlevel = "0";
			found = 1;
		}
	}
	if(found == 0){
		splitup = eregmatch( pattern: "([^-]+)-SECURITY", string: version[1] );
		if(!isnull( splitup )){
			release = splitup[1];
			log_message( port: port, data: "We have detected you are running FreeBSD " + splitup[0] + ". It also appears that you are using freebsd-update, a binary update tool for keeping your distribution up to date. We will not be able to check your core distribution for vulnerabilities, but we will check your installed ports packages." );
			found = 2;
		}
	}
	if(found == 0){
		splitup = eregmatch( pattern: "([^-]+)-(CURRENT|STABLE)", string: version[1] );
		if(!isnull( splitup )){
			release = splitup[1];
			patchlevel = "0";
			log_message( port: port, data: "We have detected you are running FreeBSD " + splitup[0] + ". It also appears that you are using a development branch of FreeBSD. Local security checks might not work as expected." );
			found = 3;
		}
	}
	if(found == 0){
		osversion = ssh_cmd( socket: sock, cmd: "uname -r" );
		log_message( port: port, data: "You appear to be running FreeBSD, but we do not recognize the output format of uname: " + uname + ". Local security checks will NOT be run." );
		os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		os_register_unknown_banner( banner: "Unknown FreeBSD release.\n\nuname -a: " + uname + "\nuname -r: " + osversion, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	if( found == 1 || found == 3 ){
		set_kb_item( name: "ssh/login/freebsdrel", value: release );
		set_kb_item( name: "ssh/login/freebsdpatchlevel", value: patchlevel );
		os_register_and_report( os: "FreeBSD", version: release, patch: "p" + patchlevel, cpe: "cpe:/o:freebsd:freebsd", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		log_message( port: port, data: create_lsc_os_detection_report( detect_text: "FreeBSD " + release + " Patch level: " + patchlevel ) );
	}
	else {
		if(found == 2){
			set_kb_item( name: "ssh/login/freebsdrel", value: release );
			os_register_and_report( os: "FreeBSD", version: release, cpe: "cpe:/o:freebsd:freebsd", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
			log_message( port: port, data: create_lsc_os_detection_report( detect_text: "FreeBSD " + release + " Patch level: Unknown" ) );
		}
	}
	if(found != 0){
		buf = ssh_cmd( socket: sock, cmd: "pkg info" );
		if(buf){
			if( ContainsString( buf, "The package management tool is not yet installed on your system" ) ){
				set_kb_item( name: "ssh/login/freebsdpkg/available", value: buf );
			}
			else {
				set_kb_item( name: "ssh/login/freebsdpkg", value: buf );
				set_kb_item( name: "ssh/login/freebsdpkg/available", value: TRUE );
			}
		}
	}
	exit( 0 );
}
if(ContainsString( uname, "SunOS " )){
	set_kb_item( name: "ssh/login/solaris", value: TRUE );
	register_uname( uname: uname );
	osversion = ssh_cmd( socket: sock, cmd: "uname -r" );
	set_kb_item( name: "ssh/login/solosversion", value: osversion );
	if( match = eregmatch( pattern: "^([0-9.]+)", string: osversion ) ){
		os_register_and_report( os: "Solaris", version: match[1], cpe: "cpe:/o:sun:solaris", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Solaris", cpe: "cpe:/o:sun:solaris", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		os_register_unknown_banner( banner: "Unknown Solaris release.\n\nuname: " + uname + "\nuname -r: " + osversion, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	hardwaretype = ssh_cmd( socket: sock, cmd: "uname -p" );
	set_kb_item( name: "ssh/login/solhardwaretype", value: hardwaretype );
	if(!is_openindiana){
		if( ContainsString( hardwaretype, "sparc" ) ){
			log_message( port: port, data: create_lsc_os_detection_report( detect_text: "Solaris " + osversion + " Arch: SPARC" ) );
		}
		else {
			log_message( port: port, data: create_lsc_os_detection_report( detect_text: "Solaris " + osversion + " Arch: x86" ) );
		}
	}
	buf = ssh_cmd( socket: sock, cmd: "pkginfo" );
	set_kb_item( name: "ssh/login/solpackages", value: buf );
	buf = ssh_cmd( socket: sock, cmd: "showrev -p" );
	set_kb_item( name: "ssh/login/solpatches", value: buf );
	exit( 0 );
}
if(ContainsString( uname, "OpenBSD " )){
	set_kb_item( name: "ssh/login/openbsd", value: TRUE );
	register_uname( uname: uname );
	osversion = ssh_cmd( socket: sock, cmd: "uname -r" );
	set_kb_item( name: "ssh/login/openbsdversion", value: osversion );
	if( match = eregmatch( pattern: "^([0-9.]+)", string: osversion ) ){
		os_register_and_report( os: "OpenBSD", version: match[1], cpe: "cpe:/o:openbsd:openbsd", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		os_register_unknown_banner( banner: "Unknown OpenBSD release.\n\nuname: " + uname + "\nuname -r: " + osversion, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	exit( 0 );
}
if(ContainsString( uname, "Darwin" )){
	register_uname( uname: uname );
	sw_vers_buf = ssh_cmd( socket: sock, cmd: "sw_vers" );
	log_message( port: 0, data: create_lsc_os_detection_report( detect_text: "\n" + sw_vers_buf ) );
	buf = chomp( ssh_cmd( socket: sock, cmd: "sw_vers -productName" ) );
	set_kb_item( name: "ssh/login/osx_name", value: buf );
	buf = chomp( ssh_cmd( socket: sock, cmd: "sw_vers -productVersion" ) );
	if( match = eregmatch( pattern: "^([0-9.]+)", string: buf ) ){
		set_kb_item( name: "ssh/login/osx_version", value: match[1] );
		os_register_and_report( os: "Mac OS X / macOS", version: match[1], cpe: "cpe:/o:apple:mac_os_x", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Mac OS X / macOS", cpe: "cpe:/o:apple:mac_os_x", banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
		os_register_unknown_banner( banner: "Unknown Mac OS X  / macOS release.\n\nsw_vers output:\n" + sw_vers_buf, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	}
	buf = chomp( ssh_cmd( socket: sock, cmd: "sw_vers -buildVersion" ) );
	set_kb_item( name: "ssh/login/osx_build", value: buf );
	buf = ssh_cmd( socket: sock, cmd: "list=$(pkgutil --pkgs);for l in $list;do echo $l;v=$(pkgutil --pkg-info $l | grep version);echo ${v#version: };done;" );
	set_kb_item( name: "ssh/login/osx_pkgs", value: buf );
	exit( 0 );
}
if(IsMatchRegexp( uname, "^Minix " )){
	register_uname( uname: uname );
	set_kb_item( name: "ssh/login/minix", value: TRUE );
	buf = chomp( ssh_cmd( socket: sock, cmd: "pkgin list" ) );
	set_kb_item( name: "ssh/login/pkgin_pkgs", value: buf );
	minix_cpe = "cpe:/o:minix3:minix";
	minix_version = eregmatch( pattern: "^Minix .* Minix ([0-9.]+) ", string: uname );
	report = "MINIX3";
	if( !isnull( minix_version[1] ) ){
		report += " " + minix_version[1];
		os_register_and_report( os: "MINIX3", version: minix_version[1], cpe: minix_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "MINIX3", cpe: minix_cpe, banner_type: "SSH login", desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	log_message( port: port, data: create_lsc_os_detection_report( no_lsc_support: TRUE, detect_text: report ) );
	exit( 0 );
}
if(!is_pfsense && !is_openindiana){
	rls = ssh_cmd( socket: sock, cmd: "cat /etc/version", return_errors: FALSE );
	if(strlen( rls )){
		_unknown_os_info += "/etc/version: " + rls + "\n\n";
	}
}
if( uname ){
	_unknown_os_info = "uname: " + uname + "\n\n" + _unknown_os_info;
	report = "System identifier unknown:\n\n";
	report += uname;
	report += "\n\nTherefore no local security checks applied (missing list of installed packages) ";
	report += "though SSH login provided and works.";
}
else {
	report = "System identifier unknown. Therefore no local security checks applied ";
	report += "(missing list of installed packages) though SSH login provided and works.";
}
if(_unknown_os_info){
	os_register_unknown_banner( banner: _unknown_os_info, banner_type_name: SCRIPT_DESC, banner_type_short: "gather_package_list", port: port );
	report += "\n\n" + "Please see the VT 'Unknown OS and Service Banner Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108441) ";
	report += "for possible ways to identify this OS.";
}
log_message( port: port, data: report );
exit( 0 );

