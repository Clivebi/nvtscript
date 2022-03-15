if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72452" );
	script_cve_id( "CVE-2012-0811", "CVE-2012-0812" );
	script_version( "2019-11-29T08:04:17+0000" );
	script_tag( name: "last_modification", value: "2019-11-29 08:04:17 +0000 (Fri, 29 Nov 2019)" );
	script_tag( name: "creation_date", value: "2012-10-03 11:11:28 -0400 (Wed, 03 Oct 2012)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Gentoo Security Advisory GLSA 201209-18 (postfixadmin)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in Postfixadmin which may
    lead to SQL injection or cross-site scripting attacks." );
	script_tag( name: "solution", value: "All Postfixadmin users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/postfixadmin-2.3.5'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-18" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=400971" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201209-18." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-apps/postfixadmin", unaffected: make_list( "ge 2.3.5" ), vulnerable: make_list( "lt 2.3.5" ) ) ) != NULL){
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

