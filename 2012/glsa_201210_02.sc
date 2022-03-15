if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72518" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-0668", "CVE-2010-0669", "CVE-2010-0717", "CVE-2010-0828", "CVE-2010-1238", "CVE-2010-2487", "CVE-2010-2969", "CVE-2010-2970", "CVE-2011-1058" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-22 08:43:43 -0400 (Mon, 22 Oct 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201210-02 (MoinMoin)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in MoinMoin, the worst of
    which allowing for injection of arbitrary web script or HTML." );
	script_tag( name: "solution", value: "All MoinMoin users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/moinmoin-1.9.4'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201210-02" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=305663" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=339295" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201210-02." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-apps/moinmoin", unaffected: make_list( "ge 1.9.4" ), vulnerable: make_list( "lt 1.9.4" ) ) ) != NULL){
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

