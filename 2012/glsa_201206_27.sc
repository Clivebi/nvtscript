if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71553" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-4490" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:53 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-27 (mini_httpd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A vulnerability in mini_httpd could allow remote attackers to
execute arbitrary code." );
	script_tag( name: "solution", value: "Gentoo discontinued support for mini_httpd. We recommend that users
      unmerge mini_httpd:

      # emerge --unmerge 'www-servers/mini_httpd'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-27" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=303755" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-27." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-servers/mini_httpd", unaffected: make_list(), vulnerable: make_list( "rle 1.19" ) ) ) != NULL){
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

