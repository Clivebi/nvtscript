if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70782" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-4028", "CVE-2011-4029" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201110-19 (xorg-server)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in the X.Org X server might allow local
    attackers to disclose information." );
	script_tag( name: "solution", value: "All X.Org X Server 1.9 users should upgrade to the latest 1.9 version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.9.5-r1'


All X.Org X Server 1.10 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.10.4-r1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-19" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=387069" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201110-19." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "x11-base/xorg-server", unaffected: make_list( "rge 1.9.5-r1",
	 "ge 1.10.4-r1" ), vulnerable: make_list( "lt 1.10.4-r1" ) ) ) != NULL){
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

