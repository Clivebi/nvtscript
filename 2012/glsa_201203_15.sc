if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71301" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4694", "CVE-2010-4695" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-15 (gif2png)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in gif2png, the worst of
    which might allow execution of arbitrary code." );
	script_tag( name: "solution", value: "All gif2png users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-gfx/gif2png-2.5.8'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-15" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=351698" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-15." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "media-gfx/gif2png", unaffected: make_list( "ge 2.5.8" ), vulnerable: make_list( "lt 2.5.8" ) ) ) != NULL){
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

