if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121395" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:28:57 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201507-14" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in Oracle JRE/JDK. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201507-14" );
	script_cve_id( "CVE-2014-3566", "CVE-2014-6549", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0400", "CVE-2015-0403", "CVE-2015-0406", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412", "CVE-2015-0413", "CVE-2015-0421" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201507-14" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-java/oracle-jre-bin", unaffected: make_list( "ge 1.8.0.31" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jre-bin", unaffected: make_list( "ge 1.7.0.76" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jre-bin", vulnerable: make_list( "le 1.8.0.31" ), unaffected: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jre-bin", vulnerable: make_list( "le 1.7.0.76" ), unaffected: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jdk-bin", unaffected: make_list( "ge 1.8.0.31" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jdk-bin", unaffected: make_list( "ge 1.7.0.76" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jdk-bin", vulnerable: make_list( "le 1.8.0.31" ), unaffected: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jdk-bin", vulnerable: make_list( "le 1.7.0.76" ), unaffected: make_list() ) ) != NULL){
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

