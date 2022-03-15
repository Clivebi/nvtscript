if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801979" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_cve_id( "CVE-2011-3351" );
	script_bugtraq_id( 49460 );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-11 18:39:00 +0000 (Wed, 11 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-01-10 17:29:46 +0530 (Tue, 10 Jan 2012)" );
	script_name( "OpenVAS Scanner Symlink Attack Local Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2011/q3/432" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/45836" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=641327" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "impact", value: "Successful exploitation allows local user on a client or server system can
  gain access to the administrator or root account thus taking full control of the system." );
	script_tag( name: "affected", value: "OpenVAS Project OpenVAS Scanner 3.2.4." );
	script_tag( name: "solution", value: "Upgrade to OpenVAS Scanner 4 or later." );
	script_tag( name: "summary", value: "This host is installed with OpenVAS Scanner and is prone to
  privilege escalation vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to the application passing a predictable temporary
  filename to the '-r' parameter of the ovaldi application, which can be
  exploited to overwrite arbitrary files via symlink attacks.

  NOTE: This vulnerability exists when ovaldi support enabled." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
for command in make_list( "openvasd" ) {
	openvasName = ssh_find_file( file_name: "/" + command + "$", useregex: TRUE, sock: sock );
	for binaryName in openvasName {
		binaryName = chomp( binaryName );
		if(!binaryName){
			continue;
		}
		openvasVer = ssh_get_bin_version( full_prog_name: binaryName, version_argv: "--version", ver_pattern: "OpenVAS.(Scanner)?.?([0-9.]+)", sock: sock );
		if(openvasVer[2]){
			if(version_is_less_equal( version: openvasVer[2], test_version: "3.2.4" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				close( sock );
				exit( 0 );
			}
		}
	}
}
close( sock );

