if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121187" );
	script_version( "2021-06-14T07:12:08+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:10 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2021-06-14 07:12:08 +0000 (Mon, 14 Jun 2021)" );
	script_name( "Gentoo Security Advisory GLSA 201405-12" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in Ettercap:" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201405-12" );
	script_cve_id( "CVE-2010-3843", "CVE-2010-3844", "CVE-2013-0722" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201405-12" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-analyzer/ettercap", unaffected: make_list( "ge 0.7.5.2" ), vulnerable: make_list( "lt 0.7.5.2" ) ) ) != NULL){
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

