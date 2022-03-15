if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121365" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:28:41 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201503-11" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in OpenSSL. Please review the CVE identifiers and the upstream advisory referenced below for details:" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201503-11" );
	script_cve_id( "CVE-2015-0204", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293", "CVE-2015-0209", "CVE-2015-0291", "CVE-2015-0290", "CVE-2015-0207", "CVE-2015-0208", "CVE-2015-1787", "CVE-2015-0285" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201503-11" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 1.0.1l-r1" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p5" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p6" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p7" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p8" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p9" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p10" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p11" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p12" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p13" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p14" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 0.9.8z_p15" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list(), vulnerable: make_list( "lt 1.0.1l-r1" ) ) ) != NULL){
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

