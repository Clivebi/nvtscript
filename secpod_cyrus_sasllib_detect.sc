if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900659" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cyrus SASL Library Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of Cyrus SASL Library." );
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
paths = ssh_find_bin( prog_name: "sasldblistusers2", sock: sock );
for saslbin in paths {
	saslbin = chomp( saslbin );
	if(!saslbin){
		continue;
	}
	saslVer = ssh_get_bin_version( full_prog_name: saslbin, sock: sock, version_argv: "-v", ver_pattern: "version ([0-9.]+)" );
	if(saslVer[1]){
		set_kb_item( name: "Cyrus/SASL/Ver", value: saslVer[1] );
		set_kb_item( name: "cyrus/sasl/dected", value: TRUE );
		register_and_report_cpe( app: "Cyrus SASL Library", ver: saslVer[1], base: "cpe:/a:cmu:cyrus-sasl:", expr: "^([0-9.]+)", regPort: 0, insloc: saslbin, concluded: saslVer[max_index( saslVer ) - 1], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

