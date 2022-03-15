if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803160" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2012-5526" );
	script_bugtraq_id( 56562 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-01-23 18:18:09 +0530 (Wed, 23 Jan 2013)" );
	script_name( "Strawberry Perl CGI.pm 'Set-Cookie' and 'P3P' HTTP Header Injection Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80098" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1027780" );
	script_xref( name: "URL", value: "http://cpansearch.perl.org/src/MARKSTOS/CGI.pm-3.63/Changes" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_perl_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Strawberry/Perl/Ver", "Strawberry/Perl/Loc" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to inject new header items
  or modify header items." );
	script_tag( name: "affected", value: "Strawberry Perl CGI.pm module before 3.63 on Windows" );
	script_tag( name: "insight", value: "The 'CGI.pm' module does not properly filter carriage returns from user
  supplied input to be used in Set-Cookie and P3P headers." );
	script_tag( name: "solution", value: "Upgrade to Strawberry Perl CGI.pm module version 3.63 or later." );
	script_tag( name: "summary", value: "The host is installed with Strawberry Perl and is prone to HTTP
  header injection vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://strawberryperl.com" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
spLoc = get_kb_item( "Strawberry/Perl/Loc" );
if(spLoc){
	insPath = spLoc + "\\perl\\lib\\CGI.PM";
	txtRead = smb_read_file( fullpath: insPath, offset: 0, count: 10000 );
	if(ContainsString( txtRead, "CGI::revision" )){
		perVer = eregmatch( pattern: "CGI::VERSION='([0-9.]+)", string: txtRead );
		if(perVer[1]){
			if(version_is_less( version: perVer[1], test_version: "3.63" )){
				report = report_fixed_ver( installed_version: perVer[1], fixed_version: "3.63", install_path: insPath );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}

