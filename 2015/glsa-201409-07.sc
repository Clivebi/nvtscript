if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121270" );
	script_version( "2020-11-12T10:09:08+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:54 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201409-07" );
	script_tag( name: "insight", value: "c-icap contains a flaw in the parse_request() function of request.c
  that may allow a remote denial of service. The issue is triggered when the buffer fails to contain a ' ' or '?' symbol,
  which will cause the end pointer to increase and surpass allocated memory. With a specially crafted request
  (e.g. via the OPTIONS method), a remote attacker can cause a loss of availability for the program." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201409-07" );
	script_cve_id( "CVE-2013-7401", "CVE-2013-7402" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201409-07" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-proxy/c-icap", unaffected: make_list( "ge 0.2.6" ), vulnerable: make_list( "lt 0.2.6" ) ) ) != NULL){
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

