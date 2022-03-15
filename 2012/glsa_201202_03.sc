if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71178" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2012-0024" );
	script_version( "2020-08-24T07:03:50+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 07:03:50 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:34 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201202-03 (maradns)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A hash collision vulnerability in MaraDNS allows remote attackers
    to cause a Denial of Service condition." );
	script_tag( name: "solution", value: "All MaraDNS users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-dns/maradns-1.4.09'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201202-03" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=397431" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201202-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-dns/maradns", unaffected: make_list( "ge 1.4.09" ), vulnerable: make_list( "lt 1.4.09" ) ) ) != NULL){
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

