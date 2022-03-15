if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121259" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:46 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201408-15" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in PostgreSQL. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201408-15" );
	script_cve_id( "CVE-2013-0255", "CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901", "CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-2669" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201408-15" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-db/postgresql-server", unaffected: make_list( "ge 9.3.3" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-db/postgresql-server", unaffected: make_list( "ge 9.2.7" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-db/postgresql-server", unaffected: make_list( "ge 9.1.12" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-db/postgresql-server", unaffected: make_list( "ge 9.0.16" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-db/postgresql-server", unaffected: make_list( "ge 8.4.20" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-db/postgresql-server", unaffected: make_list(), vulnerable: make_list( "lt 9.3.3" ) ) ) != NULL){
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

