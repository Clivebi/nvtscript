if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70795" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0520" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:41 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201111-06 (MaraDNS)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A buffer overflow vulnerability in MaraDNS allows remote attackers
    to execute arbitrary code or cause a Denial of Service." );
	script_tag( name: "solution", value: "All MaraDNS users should upgrade to the latest stable version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-dns/maradns-1.4.06'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since February 12, 2011. It is likely that your system is
      already no longer affected by this issue." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201111-06" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=352569" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201111-06." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-dns/maradns", unaffected: make_list( "ge 1.4.06" ), vulnerable: make_list( "lt 1.4.06" ) ) ) != NULL){
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

