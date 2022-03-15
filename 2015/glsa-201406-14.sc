if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121217" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:22 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201406-14" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in Opera. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201406-14" );
	script_cve_id( "CVE-2012-6461", "CVE-2012-6462", "CVE-2012-6463", "CVE-2012-6464", "CVE-2012-6465", "CVE-2012-6466", "CVE-2012-6467", "CVE-2012-6468", "CVE-2012-6469", "CVE-2012-6470", "CVE-2012-6471", "CVE-2012-6472", "CVE-2013-1618", "CVE-2013-1637", "CVE-2013-1638", "CVE-2013-1639" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201406-14" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-client/opera", unaffected: make_list( "ge 12.13_p1734" ), vulnerable: make_list( "lt 12.13_p1734" ) ) ) != NULL){
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

