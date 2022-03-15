if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105308" );
	script_cve_id( "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1792", "CVE-2015-1791", "CVE-2014-8176", "CVE-2015-3991", "CVE-2015-4171" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-11-12T11:00:41+0000" );
	script_name( "IPFire 2.17 - Core Update 91" );
	script_xref( name: "URL", value: "http://www.ipfire.org/news/ipfire-2-17-core-update-91-released" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The followinig vulnerabilities are fixed with IPFire 2.17 - Core Update 91:
OpenSSL security vulnerabilities:

There are six security vulnerabilities that are fixed in version 1.0.2b of openssl. This version contained an ABI
breakage bug that required us to wait for a fix for that and rebuild this Core Update.

Among these are fixes for the Logjam vulnerability and others that are filed under CVE-2015-1788, CVE-2015-1789,
CVE-2015-1790, CVE-2015-1792, CVE-2015-1791, and CVE-2014-8176.

StrongSwan IPsec security vulnerability:

In strongSwan 5.3.1, a security vulnerability that is filed under CVE-2015-3991 was fixed. A denial-of-service and
potential code execution was possible with specially crafted IKE messages.

IPFire ships now version 5.3.2 which fixes a second vulnerability (CVE-2015-4171)." );
	script_tag( name: "solution", value: "Update to IPFire 2.17 - Core Update 91" );
	script_tag( name: "summary", value: "IPFire 2.17 - Core Update 91 fixes multiple security vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2020-11-12 11:00:41 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-06-30 12:19:16 +0200 (Tue, 30 Jun 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_less( version: chk_version, test_version: "2.17.91" )){
	report = "Installed version: " + version + " core" + core + "\n" + "Fixed version:     2.17 core91\n";
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

