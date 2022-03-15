if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71302" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1574", "CVE-2011-2911", "CVE-2011-2912", "CVE-2011-2913", "CVE-2011-2914", "CVE-2011-2915" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-16 (libmodplug)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in ModPlug could result in execution of
    arbitrary code or Denial of Service." );
	script_tag( name: "solution", value: "All ModPlug users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libmodplug-0.8.8.4'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since August 27, 2011. It is likely that your system is
already
      no longer affected by this issue." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-16" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=362503" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=379557" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-16." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "media-libs/libmodplug", unaffected: make_list( "ge 0.8.8.4" ), vulnerable: make_list( "lt 0.8.8.4" ) ) ) != NULL){
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

