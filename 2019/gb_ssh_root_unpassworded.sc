if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108587" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_cve_id( "CVE-2019-5021", "CVE-1999-0502" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 12:29:00 +0000 (Mon, 03 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-05-24 12:35:09 +0000 (Fri, 24 May 2019)" );
	script_name( "Unpassworded 'root' Account (SSH)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "os_detection.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0782" );
	script_xref( name: "URL", value: "https://alpinelinux.org/posts/Docker-image-vulnerability-CVE-2019-5021.html" );
	script_tag( name: "summary", value: "The remote host has set no password for the root account." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with a 'root' username and without a password." );
	script_tag( name: "insight", value: "It was possible to login with the 'root' username and without passing
  a password." );
	script_tag( name: "affected", value: "Versions of the Official Alpine Linux Docker images (since v3.3) are
  known to be affected. Other products / devices might be affected as well." );
	script_tag( name: "solution", value: "Set a password for the 'root' account. If this is an Alpine Linux Docker image
  update to one of the following image releases:

  edge (20190228 snapshot), v3.9.2, v3.8.4, v3.7.3, v3.6.5." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
login = ssh_login( socket: soc, login: "root", password: "", priv: NULL, passphrase: NULL );
if(login == 0){
	files = traversal_files( "linux" );
	for pattern in keys( files ) {
		file = "/" + files[pattern];
		cmd = ssh_cmd( socket: soc, cmd: "cat " + file, nosh: TRUE );
		if(egrep( string: cmd, pattern: pattern, icase: TRUE )){
			if(soc){
				close( soc );
			}
			report = "It was possible to login as user `root` without a password and to execute `cat " + file + "`. Result:\n\n" + cmd;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
if(soc){
	close( soc );
}
exit( 99 );

