if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71190" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0010", "CVE-2012-0809" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:35 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-06 (sudo)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in sudo, allowing local
    attackers to possibly gain escalated privileges." );
	script_tag( name: "solution", value: "All sudo users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-admin/sudo-1.8.3_p2'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-06" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=351490" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=401533" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-06." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-admin/sudo", unaffected: make_list( "ge 1.8.3_p2",
	 "rge 1.7.4_p5" ), vulnerable: make_list( "lt 1.8.3_p2" ) ) ) != NULL){
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

