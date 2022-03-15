if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71568" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-4838" );
	script_version( "2021-01-15T07:53:46+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:53:46 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:54 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201207-06 (jruby)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A hash collision vulnerability in JRuby allows remote attackers to
cause a Denial of Service condition." );
	script_tag( name: "solution", value: "All JRuby users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/jruby-1.6.5.1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201207-06" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=396305" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201207-06." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-java/jruby", unaffected: make_list( "ge 1.6.5.1" ), vulnerable: make_list( "lt 1.6.5.1" ) ) ) != NULL){
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

