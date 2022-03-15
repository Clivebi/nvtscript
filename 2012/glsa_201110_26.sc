if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70789" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-4008", "CVE-2010-4494", "CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201110-26 (libxml2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in libxml2 which could lead to
    execution of arbitrary code or a Denial of Service." );
	script_tag( name: "solution", value: "All libxml2 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/libxml2-2.7.8-r3'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-26" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=345555" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=370715" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=386985" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201110-26." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-libs/libxml2", unaffected: make_list( "ge 2.7.8-r3" ), vulnerable: make_list( "lt 2.7.8-r3" ) ) ) != NULL){
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

