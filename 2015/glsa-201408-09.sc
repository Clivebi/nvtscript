if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121253" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:43 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201408-09" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in GNU Libtasn1. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201408-09" );
	script_cve_id( "CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201408-09" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-libs/libtasn1", unaffected: make_list( "ge 3.6" ), vulnerable: make_list( "lt 3.6" ) ) ) != NULL){
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

