if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802344" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_cve_id( "CVE-2011-4000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2011-11-11 14:20:07 +0530 (Fri, 11 Nov 2011)" );
	script_name( "ChaSen Buffer Overflow Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN16901583/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000099.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to cause a buffer overflow
  or execute arbitrary code." );
	script_tag( name: "affected", value: "ChaSen Version 2.4.x." );
	script_tag( name: "insight", value: "The flaw is due to an error when reading user-supplied input string,
  which allows attackers to execute arbitrary code via a crafted string." );
	script_tag( name: "solution", value: "Use ChaSen Version 2.3.3." );
	script_tag( name: "summary", value: "The host is running ChaSen Software and is prone to buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
chaName = ssh_find_file( file_name: "/chasen-config$", useregex: TRUE, sock: sock );
for binaryName in chaName {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	chaVer = ssh_get_bin_version( full_prog_name: binaryName, version_argv: "--version", ver_pattern: "[0-9.]{5,}", sock: sock );
	if(!isnull( chaVer[1] )){
		if(version_in_range( version: chaVer[1], test_version: "2.4.0", test_version2: "2.4.4" )){
			report = report_fixed_ver( installed_version: chaVer[1], fixed_version: "2.3.3 or a later 2.4 version" );
			security_message( port: 0, data: report );
			ssh_close_connection();
			exit( 0 );
		}
	}
}
ssh_close_connection();
exit( 0 );

