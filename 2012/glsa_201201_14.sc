if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70815" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1526", "CVE-2011-4862" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:42 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201201-14 (mit-krb5-appl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in MIT Kerberos 5
    Applications, the most severe of which may allow execution of
arbitrary
    code." );
	script_tag( name: "solution", value: "All MIT Kerberos 5 Applications users should upgrade to the latest
      version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-crypt/mit-krb5-appl-1.0.2-r1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-14" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=374229" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=396137" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201201-14." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-crypt/mit-krb5-appl", unaffected: make_list( "ge 1.0.2-r1" ), vulnerable: make_list( "lt 1.0.2-r1" ) ) ) != NULL){
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

