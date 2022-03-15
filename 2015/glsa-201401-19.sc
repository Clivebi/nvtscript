if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121116" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:26:36 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201401-19" );
	script_tag( name: "insight", value: "GMime contains a buffer overflow flaw in the GMIME_UUENCODE_LEN macro in gmime/gmime-encodings.h." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201401-19" );
	script_cve_id( "CVE-2010-0409" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201401-19" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-libs/gmime", unaffected: make_list( "ge 2.4.15" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/gmime", unaffected: make_list( "ge 2.4.17" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/gmime", unaffected: make_list( "ge 2.2.26" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/gmime", unaffected: make_list(), vulnerable: make_list( "lt 2.4.15" ) ) ) != NULL){
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

