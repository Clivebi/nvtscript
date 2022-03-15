if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70817" );
	script_cve_id( "CVE-2012-0064" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:42 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201201-16 (xkeyboard-config xorg-server)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A debugging functionality in the X.Org X Server that is bound to a
    hotkey by default can be used by local attackers to circumvent screen
    locking utilities." );
	script_tag( name: "solution", value: "All xkeyboard-config users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-misc/xkeyboard-config-2.4.1-r3'


NOTE: The X.Org X Server 1.11 was only stable on the AMD64, ARM, HPPA,
      and x86 architectures. Users of the stable branches of all other
      architectures are not affected and will be directly provided with a
fixed
      X Keyboard Configuration Database version." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-16" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=399347" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201201-16." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "x11-misc/xkeyboard-config", unaffected: make_list( "ge 2.4.1-r3" ), vulnerable: make_list( "lt 2.4.1-r3" ) ) ) != NULL){
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

