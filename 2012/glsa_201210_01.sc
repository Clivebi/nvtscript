if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72517" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2074" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-22 08:43:43 -0400 (Mon, 22 Oct 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201210-01 (w3m)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "An error in the hostname matching of w3m might enable remote
    attackers to conduct man-in-the-middle attacks." );
	script_tag( name: "solution", value: "All w3m users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/w3m-0.5.2-r4'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201210-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=325431" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201210-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-client/w3m", unaffected: make_list( "ge 0.5.2-r4" ), vulnerable: make_list( "lt 0.5.2-r4" ) ) ) != NULL){
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

