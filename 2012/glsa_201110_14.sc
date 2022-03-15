if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70777" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4352", "CVE-2011-2200", "CVE-2011-2533" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:39 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201110-14 (D-Bus)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in D-Bus, the worst of which
    allowing for a symlink attack." );
	script_tag( name: "solution", value: "All D-Bus users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-apps/dbus-1.4.12'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-14" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=348766" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=371261" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=372743" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201110-14." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "sys-apps/dbus", unaffected: make_list( "ge 1.4.12" ), vulnerable: make_list( "lt 1.4.12" ) ) ) != NULL){
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

