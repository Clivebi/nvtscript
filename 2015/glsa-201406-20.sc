if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121223" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:25 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201406-20" );
	script_tag( name: "insight", value: "A bug in the SPDY implementation in nginx was found which might cause a heap memory buffer overflow in a worker process by using a specially crafted request. The SPDY implementation is not enabled in default configurations." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201406-20" );
	script_cve_id( "CVE-2014-0133" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201406-20" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-servers/nginx", unaffected: make_list( "ge 1.4.7" ), vulnerable: make_list( "lt 1.4.7" ) ) ) != NULL){
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

