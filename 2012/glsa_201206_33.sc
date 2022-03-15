if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71559" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0411", "CVE-2011-1720" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:54 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-33 (Postfix)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A vulnerability has been found in Postfix, the worst of which
possibly allowing remote code execution." );
	script_tag( name: "solution", value: "All Postfix users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.7.4'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-33" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=358085" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=366605" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-33." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "mail-mta/postfix", unaffected: make_list( "ge 2.7.4" ), vulnerable: make_list( "lt 2.7.4" ) ) ) != NULL){
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

