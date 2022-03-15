if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71566" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2118" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:54 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201207-04 (xorg-server)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A format string vulnerability in X.Org X Server may allow local
privilege escalation or Denial of Service." );
	script_tag( name: "solution", value: "All X.Org X Server 1.11.x users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.11.4-r1'


All X.Org X Server 1.10.x users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.10.6-r1'


X.Org X Server 1.9.x is not affected." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201207-04" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=412609" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201207-04." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "x11-base/xorg-server", unaffected: make_list( "ge 1.11.4-r1",
	 "rge 1.10.6-r1",
	 "rle 1.9.5-r1" ), vulnerable: make_list( "lt 1.11.4-r1" ) ) ) != NULL){
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

