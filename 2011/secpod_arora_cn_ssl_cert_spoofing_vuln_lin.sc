if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902764" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3367" );
	script_bugtraq_id( 49925 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-15 14:01:47 +0530 (Thu, 15 Dec 2011)" );
	script_name( "Arora Common Name SSL Certificate Spoofing Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46269" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520041" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=746875" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2011-10/att-0353/NDSA20111003.txt.asc" );
	script_tag( name: "insight", value: "The flaw is due to not using a certain font when rendering
  certificate fields in a security dialog." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Arora and is prone common name SSL
  certificate spoofing vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to spoof the
  common name (CN) of a certificate via rich text." );
	script_tag( name: "affected", value: "Arora version 0.11 and prior." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = NASLString( "[0]\\\\.[0-9][0-9]\\\\.[0-9]" );
modName = ssh_find_file( file_name: "/arora$", useregex: TRUE, sock: sock );
for binaryName in modName {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[3] + raw_string( 0x22 ) + " " + binaryName;
	arrVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg, ver_pattern: "([0-9.]+)", sock: sock );
	if(arrVer[1]){
		if(version_is_less_equal( version: arrVer[1], test_version: "0.11.0" )){
			report = report_fixed_ver( installed_version: arrVer[1], fixed_version: "WillNotFix", install_path: binaryName );
			security_message( port: 0, data: report );
			ssh_close_connection();
			exit( 0 );
		}
	}
}
ssh_close_connection();
exit( 0 );

