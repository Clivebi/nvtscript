CPE = "cpe:/a:perl:perl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108504" );
	script_version( "2021-07-19T06:58:54+0000" );
	script_tag( name: "last_modification", value: "2021-07-19 06:58:54 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-12-10 09:46:38 +0100 (Mon, 10 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Perl Modules Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_perl_consolidation.sc" );
	script_mandatory_keys( "perl/ssh-login/detected" );
	script_tag( name: "summary", value: "SSH login-based detection of various installed Perl modules." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
if(isnull( port = get_app_port( cpe: CPE, service: "ssh-login" ) )){
	exit( 0 );
}
if(!bin = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
cmd = NASLString( bin, " -MArchive::Tar -e 'print ", "\"$Archive::Tar::VERSION\"", "'" );
version = ssh_cmd( socket: sock, cmd: cmd, timeout: 60, nosh: TRUE );
version = chomp( version );
if(version && !ContainsString( version, "not found" ) && !ContainsString( version, "@INC" ) && IsMatchRegexp( version, "^[0-9.]{3,}$" )){
	set_kb_item( name: "perl/ssh-login/modules/detected", value: TRUE );
	set_kb_item( name: "perl/ssh-login/modules/archive_tar/detected", value: TRUE );
	register_and_report_cpe( app: "Perl Module Archive::Tar", ver: version, base: "cpe:/a:perl:archive_tar:", expr: "([0-9.]+)", regPort: 0, insloc: bin, concluded: version, regService: "ssh-login", extra: "Command used for the detection: " + cmd );
}
cmd = NASLString( bin, " -MCGI -e 'print ", "\"$CGI::VERSION\"", "'" );
version = ssh_cmd( socket: sock, cmd: cmd, timeout: 60, nosh: TRUE );
version = chomp( version );
if(version && !ContainsString( version, "not found" ) && !ContainsString( version, "@INC" ) && IsMatchRegexp( version, "^[0-9.]{3,}$" )){
	set_kb_item( name: "perl/ssh-login/modules/detected", value: TRUE );
	set_kb_item( name: "perl/ssh-login/modules/cgi/detected", value: TRUE );
	register_and_report_cpe( app: "Perl Module CGI", ver: version, base: "cpe:/a:andy_armstrong:cgi.pm:", expr: "([0-9.]+)", regPort: 0, insloc: bin, concluded: version, regService: "ssh-login", extra: "Command used for the detection: " + cmd );
}
cmd = NASLString( bin, " -MIO::Socket::SSL -e 'print ", "\"$IO::Socket::SSL::VERSION\"", "'" );
version = ssh_cmd( socket: sock, cmd: cmd, timeout: 60, nosh: TRUE );
version = chomp( version );
if(version && !ContainsString( version, "not found" ) && !ContainsString( version, "@INC" ) && IsMatchRegexp( version, "^[0-9.]{3,}$" )){
	set_kb_item( name: "perl/ssh-login/modules/detected", value: TRUE );
	set_kb_item( name: "perl/ssh-login/modules/io_socket_ssl/detected", value: TRUE );
	register_and_report_cpe( app: "Perl Module IO::Socket::SSL", ver: version, base: "cpe:/a:io-socket-ssl:io-socket-ssl:", expr: "([0-9.]+)", regPort: 0, insloc: bin, concluded: version, regService: "ssh-login", extra: "Command used for the detection: " + cmd );
}
cmd = NASLString( bin, " -MSafe -e 'print ", "\"$Safe::VERSION\"", "'" );
version = ssh_cmd( socket: sock, cmd: cmd, timeout: 60, nosh: TRUE );
version = chomp( version );
if(version && !ContainsString( version, "not found" ) && !ContainsString( version, "@INC" ) && IsMatchRegexp( version, "^[0-9.]{3,}$" )){
	set_kb_item( name: "perl/ssh-login/modules/detected", value: TRUE );
	set_kb_item( name: "perl/ssh-login/modules/safe/detected", value: TRUE );
	register_and_report_cpe( app: "Perl Module Safe", ver: version, base: "cpe:/a:rafael_garcia-suarez:safe:", expr: "([0-9.]+)", regPort: 0, insloc: bin, concluded: version, regService: "ssh-login", extra: "Command used for the detection: " + cmd );
}
ssh_close_connection();
exit( 0 );

