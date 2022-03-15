if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812199" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-11-28 12:44:53 +0530 (Tue, 28 Nov 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Tor Browser Bundle Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detection of presence of Tor Browser
  Bundle.

  The script logs in via ssh, searches for executable 'tor browser' and gets
  the version from Doc file." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ssh_func.inc.sc");
tor_sock = ssh_login_or_reuse_connection();
if(!tor_sock){
	exit( 0 );
}
torNames = ssh_find_file( file_name: "/versions$", useregex: TRUE, sock: tor_sock );
for binaryName in torNames {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	if(( ContainsString( binaryName, "TorBrowser" ) || ContainsString( binaryName, "tor-browser" ) ) && ( IsMatchRegexp( binaryName, "Docs/Sources/Versions" ) )){
		torVer = ssh_get_bin_version( full_prog_name: "cat", version_argv: binaryName, ver_pattern: "TORBROWSER_VERSION=([0-9.]+)", sock: tor_sock );
		if(torVer[1]){
			version = torVer[1];
			set_kb_item( name: "TorBrowser/Linux/Ver", value: version );
			register_and_report_cpe( app: "Tor Browser Bundle", ver: version, concluded: version, base: "cpe:/a:tor:tor:", expr: "^([0-9.]+-?([a-z0-9]+)?)", insloc: binaryName );
		}
	}
}
ssh_close_connection();
exit( 0 );

