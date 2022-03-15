if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69027" );
	script_version( "$Revision: 14171 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 11:22:03 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-1646", "CVE-2010-2956" );
	script_name( "Gentoo Security Advisory GLSA 201009-03 (sudo)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "The secure path feature and group handling in sudo allow local attackers to
    escalate privileges." );
	script_tag( name: "solution", value: "All sudo users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/sudo-1.7.4_p3-r1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201009-03" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=322517" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=335381" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201009-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
report = "";
if(( res = ispkgvuln( pkg: "app-admin/sudo", unaffected: make_list( "ge 1.7.4_p3-r1" ), vulnerable: make_list( "lt 1.7.4_p3-r1" ) ) ) != NULL){
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

