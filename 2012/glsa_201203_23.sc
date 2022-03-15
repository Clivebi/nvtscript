if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71309" );
	script_cve_id( "CVE-2012-1162", "CVE-2012-1163" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-23 (libzip)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in libzip, the worst of
    which might allow execution of arbitrary code." );
	script_tag( name: "solution", value: "All libzip users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/libzip-0.10.1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-23" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=409117" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-23." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-libs/libzip", unaffected: make_list( "ge 0.10.1" ), vulnerable: make_list( "lt 0.10.1" ) ) ) != NULL){
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

