if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802164" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)" );
	script_cve_id( "CVE-2010-4340" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Libcloud SSL Certificates Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://wiki.apache.org/incubator/LibcloudSSL" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/LIBCLOUD-55" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=598463" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to spoof certificates and
  bypass intended access restrictions via a man-in-the-middle (MITM) attack." );
	script_tag( name: "affected", value: "libcloud version prior to 0.4.1." );
	script_tag( name: "insight", value: "The flaw is due to improper verification of SSL certificates for
  HTTPS connections." );
	script_tag( name: "solution", value: "Upgrade to  libcloud version 0.4.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Libcloud and is prone to security
  bypass vulnerability." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
libName = ssh_find_file( file_name: "/libcloud/__init__\\.py$", useregex: TRUE, sock: sock );
if(libName){
	for binaryName in libName {
		binaryName = chomp( binaryName );
		if(!binaryName){
			continue;
		}
		libVer = ssh_get_bin_version( full_prog_name: "cat", sock: sock, version_argv: binaryName, ver_pattern: "= '([0-9.]+)'" );
		if(libVer[1]){
			if(version_is_less( version: libVer[1], test_version: "0.4.1" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				close( sock );
				exit( 0 );
			}
		}
	}
}
close( sock );

