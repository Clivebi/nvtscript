if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105321" );
	script_cve_id( "CVE-2015-1793", "CVE-2015-5400" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 12106 $" );
	script_name( "IPFire 2.17 - Core Update 92" );
	script_xref( name: "URL", value: "http://www.ipfire.org/news/ipfire-2-17-core-update-92-released" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The followinig vulnerabilities are fixed with IPFire 2.17 - Core Update 92:

openssl 1.0.2d
The openssl package has been updated to version 1.0.2d because of a high severity security fix filed under CVE-2015-1793.

Squid Advisory SQUID-2015:2
This update comes with a patched version of squid to fix SQUID-2015:2." );
	script_tag( name: "solution", value: "Update to IPFire 2.17 - Core Update 92" );
	script_tag( name: "summary", value: "IPFire 2.17 - Core Update 92 fixes multiple security vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-18 13:35:54 +0200 (Tue, 18 Aug 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ipfire/system-release" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!rls = get_kb_item( "ipfire/system-release" )){
	exit( 0 );
}
if(!ContainsString( rls, "IPFire" )){
	exit( 0 );
}
vers = eregmatch( pattern: "IPFire ([0-9.]+[^ ]*)", string: rls );
if(!isnull( vers[1] )){
	version = vers[1];
}
if(!version){
	exit( 0 );
}
c = eregmatch( pattern: "core([0-9]+)", string: rls );
if( !isnull( c[1] ) ) {
	core = c[1];
}
else {
	core = 0;
}
chk_version = version + "." + core;
if(version_is_less( version: chk_version, test_version: "2.17.92" )){
	report = "Installed version: " + version + " core" + core + "\n" + "Fixed version:     2.17 core92\n";
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

