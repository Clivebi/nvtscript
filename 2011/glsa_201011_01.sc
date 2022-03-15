if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69035" );
	script_version( "$Revision: 14171 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 11:22:03 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4880", "CVE-2009-4881", "CVE-2010-0296", "CVE-2010-0830", "CVE-2010-3847", "CVE-2010-3856" );
	script_name( "Gentoo Security Advisory GLSA 201011-01 (glibc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in glibc, the worst of which allowing
    local attackers to execute arbitrary code as root." );
	script_tag( name: "solution", value: "All GNU C library users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-libs/glibc-2.11.2-r3'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201011-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=285818" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=325555" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=330923" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=335871" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=341755" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201011-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
report = "";
if(( res = ispkgvuln( pkg: "sys-libs/glibc", unaffected: make_list( "ge 2.11.2-r3" ), vulnerable: make_list( "lt 2.11.2-r3" ) ) ) != NULL){
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

