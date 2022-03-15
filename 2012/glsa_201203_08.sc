if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71192" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-3970" );
	script_version( "2020-04-21T07:31:29+0000" );
	script_tag( name: "last_modification", value: "2020-04-21 07:31:29 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:35 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-08 (libxslt)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A vulnerability in libxslt could result in Denial of Service." );
	script_tag( name: "solution", value: "All libxslt users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/libxslt-1.1.26-r3'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-08" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=402861" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-08." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-libs/libxslt", unaffected: make_list( "ge 1.1.26-r3" ), vulnerable: make_list( "lt 1.1.26-r3" ) ) ) != NULL){
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

