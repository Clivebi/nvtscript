if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72200" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-1535", "CVE-2012-4163", "CVE-2012-4164", "CVE-2012-4165", "CVE-2012-4166", "CVE-2012-4167", "CVE-2012-4168" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:26:21 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201209-01 (adobe-flash)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in Adobe Flash Player, the
    worst of which could result in execution of arbitrary code." );
	script_tag( name: "solution", value: "All Adobe Flash Player users should upgrade to the latest version:

  # emerge --sync
  # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-11.2.202.238'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=431432" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=432286" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201209-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-plugins/adobe-flash", unaffected: make_list( "ge 11.2.202.238" ), vulnerable: make_list( "lt 11.2.202.238" ) ) ) != NULL){
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

