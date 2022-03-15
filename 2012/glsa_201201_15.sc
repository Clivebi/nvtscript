if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70816" );
	script_cve_id( "CVE-2011-2921", "CVE-2011-2922" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-08-27T12:57:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:57:20 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-21 18:55:00 +0000 (Thu, 21 Nov 2019)" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:42 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201201-15 (ktsuss)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Two vulnerabilities have been found in ktsuss, allowing local
    attackers to gain escalated privileges." );
	script_tag( name: "solution", value: "Gentoo discontinued support for ktsuss. We recommend that users unmerge
      ktsuss:

      # emerge --unmerge 'x11-misc/ktsuss'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-15" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=381115" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201201-15." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "x11-misc/ktsuss", unaffected: make_list(), vulnerable: make_list( "le 1.4" ) ) ) != NULL){
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

