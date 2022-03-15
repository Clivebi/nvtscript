if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71194" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-2546", "CVE-2010-2971" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:35 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-10 (libmikmod)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple buffer overflow vulnerabilities in libmikmod may allow an
    attacker to execute arbitrary code or cause a Denial of Service
condition." );
	script_tag( name: "solution", value: "All libmikmod 3.2 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libmikmod-3.2.0_beta2-r3'


All libmikmod 3.1 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libmikmod-3.1.12-r1'


Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying some of these
packages." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-10" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=335892" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-10." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "media-libs/libmikmod", unaffected: make_list( "ge 3.2.0_beta2-r3",
	 "rge 3.1.12-r1" ), vulnerable: make_list( "lt 3.2.0_beta2-r3" ) ) ) != NULL){
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

