if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71587" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-2485", "CVE-2012-2370" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:56 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-20 (gdk-pixbuf)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in gdk-pixbuf may create a Denial of
Service condition." );
	script_tag( name: "solution", value: "All gdk-pixbuf users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/gdk-pixbuf-2.24.1-r1'


Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying some of these
packages." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-20" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=373999" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=412033" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-20." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "x11-libs/gdk-pixbuf", unaffected: make_list( "ge 2.24.1-r1" ), vulnerable: make_list( "lt 2.24.1-r1" ) ) ) != NULL){
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

