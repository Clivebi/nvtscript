if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72425" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-3501" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-26 11:20:49 -0400 (Wed, 26 Sep 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201209-08 (squidclamav)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A vulnerability in SquidClamav may result in Denial of Service." );
	script_tag( name: "solution", value: "All SquidClamav users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-proxy/squidclamav-6.8'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-08" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=428778" );
	script_xref( name: "URL", value: "http://squidclamav.darold.net/news.html" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201209-08." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-proxy/squidclamav", unaffected: make_list( "ge 6.8" ), vulnerable: make_list( "lt 6.8" ) ) ) != NULL){
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

