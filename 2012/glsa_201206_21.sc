if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71588" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0779", "CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037", "CVE-2012-2038", "CVE-2012-2039", "CVE-2012-2040" );
	script_version( "2020-08-18T09:42:52+0000" );
	script_tag( name: "last_modification", value: "2020-08-18 09:42:52 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:56 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-21 (Adobe Flash Player)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in Adobe Flash Player
could result in the execution of arbitrary code or Denial of Service." );
	script_tag( name: "solution", value: "All Adobe Flash Player users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-11.2.202.236'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-21" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=414603" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=420311" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-21." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-plugins/adobe-flash", unaffected: make_list( "ge 11.2.202.236" ), vulnerable: make_list( "lt 11.2.202.236" ) ) ) != NULL){
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

