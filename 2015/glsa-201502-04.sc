if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121343" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:28:28 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201502-04" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in MediaWiki. Please review the CVE identifiers and MediaWiki announcement referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201502-04" );
	script_cve_id( "CVE-2013-6451", "CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6454", "CVE-2013-6472", "CVE-2014-1610", "CVE-2014-2242", "CVE-2014-2243", "CVE-2014-2244", "CVE-2014-2665", "CVE-2014-2853", "CVE-2014-5241", "CVE-2014-5242", "CVE-2014-5243", "CVE-2014-7199", "CVE-2014-7295", "CVE-2014-9276", "CVE-2014-9277", "CVE-2014-9475", "CVE-2014-9476", "CVE-2014-9477", "CVE-2014-9478", "CVE-2014-9479", "CVE-2014-9480", "CVE-2014-9481", "CVE-2014-9487", "CVE-2014-9507" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201502-04" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-apps/mediawiki", unaffected: make_list( "ge 1.23.8" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "www-apps/mediawiki", unaffected: make_list( "ge 1.22.15" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "www-apps/mediawiki", unaffected: make_list( "ge 1.19.23" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "www-apps/mediawiki", unaffected: make_list(), vulnerable: make_list( "lt 1.23.8" ) ) ) != NULL){
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

