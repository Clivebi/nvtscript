if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121155" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:26:56 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201402-24" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in GnuPG and Libgcrypt. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201402-24" );
	script_cve_id( "CVE-2012-6085", "CVE-2013-4242", "CVE-2013-4351", "CVE-2013-4402" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201402-24" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-crypt/gnupg", unaffected: make_list( "ge 2.0.22" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-crypt/gnupg", unaffected: make_list( "ge 1.4.16" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-crypt/gnupg", unaffected: make_list( "ge 1.4.17" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-crypt/gnupg", unaffected: make_list( "ge 1.4.18" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-crypt/gnupg", unaffected: make_list( "ge 1.4.19" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-crypt/gnupg", unaffected: make_list( "ge 1.4.20" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-crypt/gnupg", unaffected: make_list(), vulnerable: make_list( "lt 2.0.22" ) ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/libgcrypt", unaffected: make_list( "ge 1.5.3" ), vulnerable: make_list( "lt 1.5.3" ) ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

