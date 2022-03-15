if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811904" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2017-09-20 18:25:25 +0530 (Wed, 20 Sep 2017)" );
	script_name( "IBM Websphere MQ Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script search for 'dspmqver' and queries for IBM Mq version." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "dspmqver", sock: sock );
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	version = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-v", ver_pattern: "Version:\\s+([0-9.]+)" );
	if(!isnull( version[1] )){
		set_kb_item( name: "ibm_websphere_mq/detected", value: TRUE );
		set_kb_item( name: "ibm_websphere_mq/lin/local/version", value: version[1] );
		set_kb_item( name: "ibm_websphere_mq/lin/local/path", value: bin );
		close( sock );
		exit( 0 );
	}
}
close( sock );
exit( 0 );

