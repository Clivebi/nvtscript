if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111108" );
	script_version( "2021-02-02T12:11:39+0000" );
	script_tag( name: "last_modification", value: "2021-02-02 12:11:39 +0000 (Tue, 02 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-07-06 16:00:00 +0200 (Wed, 06 Jul 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Linux Home Folder Accessible" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script attempts to identify files of a linux home folder
  accessible at the webserver." );
	script_tag( name: "insight", value: "Currently the script is checking for the following files:

  - /.ssh/authorized_keys

  - /.ssh/config

  - /.ssh/known_hosts

  - /.ssh/identity

  - /.ssh/id_rsa

  - /.ssh/id_rsa.pub

  - /.ssh/id_dsa

  - /.ssh/id_dsa.pub

  - /.ssh/id_dss

  - /.ssh/id_dss.pub

  - /.ssh/id_ecdsa

  - /.ssh/id_ecdsa.pub

  - /.ssh/id_ed25519

  - /.ssh/id_ed25519.pub

  - /.mysql_history

  - /.sqlite_history

  - /.psql_history

  - /.sh_history

  - /.bash_history

  - /.profile

  - /.bashrc" );
	script_tag( name: "vuldetect", value: "Check the response if files from a home folder are accessible." );
	script_tag( name: "impact", value: "Based on the information provided in this files an attacker might
  be able to gather additional info." );
	script_tag( name: "solution", value: "A users home folder shouldn't be accessible via a webserver.
  Restrict access to it or remove it completely." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_timeout( 600 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
files = make_array( "/.ssh/authorized_keys", "^(ecdsa-sha2-nistp256|ssh-rsa|ssh-dsa|ssh-dss|ssh-ed25519)", "/.ssh/config", "^\\s*(Host (\\*|a-z])|(HostName|LogLevel|Compression|IdentityFile|ForwardAgent|ForwardX11|ForwardX11Trusted|ProxyCommand|LocalForward) )", "/.ssh/known_hosts", "(ecdsa-sha2-nistp256|ssh-rsa|ssh-dsa|ssh-dss|ssh-ed25519)", "/.ssh/identity", "^SSH PRIVATE KEY FILE FORMAT", "/.ssh/id_rsa", "^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----", "/.ssh/id_rsa.pub", "^ssh-rsa", "/.ssh/id_dsa", "^-----(BEGIN|END) (DSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----", "/.ssh/id_dsa.pub", "^ssh-dsa", "/.ssh/id_dss", "^-----(BEGIN|END) (DSS|ENCRYPTED|OPENSSH) PRIVATE KEY-----", "/.ssh/id_dss.pub", "^ssh-dss", "/.ssh/id_ecdsa", "^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----", "/.ssh/id_ecdsa.pub", "^ecdsa-sha2-nistp256", "/.ssh/id_ed25519", "^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----", "/.ssh/id_ed25519.pub", "^ssh-ed25519", "/.mysql_history", "^(INSERT INTO |DELETE FROM |(DROP|CREATE) TABLE |(DROP|CREATE) (DATABASE|SCHEMA) |SELECT ALL |GRANT ALL ON |FLUSH PRIVILEGES)", "/.sqlite_history", "^(INSERT INTO |DELETE FROM |(DROP|CREATE) TABLE |(DROP|CREATE) (DATABASE|SCHEMA) |SELECT ALL |\\.tables|\\.quit|\\.databases)", "/.psql_history", "^(INSERT INTO |DELETE FROM |(DROP|CREATE) TABLE |(DROP|CREATE) (DATABASE|SCHEMA) |SELECT ALL |GRANT ALL ON )", "/.sh_history", "^(less|more|wget |curl |grep |chmod |chown |iptables|ifconfig|history|touch |head|tail|mkdir |sudo)", "/.bash_history", "^(less|more|wget |curl |grep |chmod |chown |iptables|ifconfig|history|touch |head|tail|mkdir |sudo)", "/.profile", "^# ~/\\.profile:", "/.bashrc", "^# ~/\\.bashrc:" );
report = "The following files were identified:\n";
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = dir + file;
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: files[file], usecache: TRUE )){
			report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			VULN = TRUE;
		}
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

