if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69028" );
	script_version( "$Revision: 14171 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 11:22:03 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-1922" );
	script_name( "Gentoo Security Advisory GLSA 201009-04 (SARG sarg)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple stack-based buffer overflow vulnerabilities were discovered in
    SARG allowing for remote code execution." );
	script_tag( name: "solution", value: "All SARG users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/sarg-2.2.5-r5'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201009-04" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=222121" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201009-04." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
report = "";
if(( res = ispkgvuln( pkg: "net-analyzer/sarg", unaffected: make_list( "ge 2.2.5-r5" ), vulnerable: make_list( "lt 2.2.5-r5" ) ) ) != NULL){
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

