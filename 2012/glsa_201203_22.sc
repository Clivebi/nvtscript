if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71308" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3555", "CVE-2009-3896", "CVE-2009-3898", "CVE-2011-4315", "CVE-2012-1180" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-22 (nginx)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in nginx, the worst of
    which may allow execution of arbitrary code." );
	script_tag( name: "solution", value: "All nginx users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/nginx-1.0.14'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-22" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=293785" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=293786" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=293788" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=389319" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=408367" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-22." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-servers/nginx", unaffected: make_list( "ge 1.0.14" ), vulnerable: make_list( "lt 1.0.14" ) ) ) != NULL){
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

