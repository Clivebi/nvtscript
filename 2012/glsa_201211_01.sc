if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72582" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3303", "CVE-2010-3763", "CVE-2010-4348", "CVE-2010-4349", "CVE-2010-4350", "CVE-2011-2938", "CVE-2011-3356", "CVE-2011-3357", "CVE-2011-3358", "CVE-2011-3578", "CVE-2011-3755", "CVE-2012-1118", "CVE-2012-1119", "CVE-2012-1120", "CVE-2012-1121", "CVE-2012-1122", "CVE-2012-1123", "CVE-2012-2691", "CVE-2012-2692" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-11-16 03:21:29 -0500 (Fri, 16 Nov 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201211-01 (MantisBT)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in MantisBT, the worst of
which allowing for local file inclusion." );
	script_tag( name: "solution", value: "All MantisBT users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mantisbt-1.2.11'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201211-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=348761" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=381417" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=386153" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=407121" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=420375" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201211-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-apps/mantisbt", unaffected: make_list( "ge 1.2.11" ), vulnerable: make_list( "lt 1.2.11" ) ) ) != NULL){
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

