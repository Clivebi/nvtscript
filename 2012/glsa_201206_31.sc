if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71557" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3316", "CVE-2010-3430", "CVE-2010-3431", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-4706", "CVE-2010-4707", "CVE-2010-4708", "CVE-2011-3148", "CVE-2011-3149" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:53 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-31 (pam)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in Linux-PAM, allowing
local attackers to possibly gain escalated privileges, cause a Denial
of Service, corrupt data, or obtain sensitive information." );
	script_tag( name: "solution", value: "All Linux-PAM users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-libs/pam-1.1.5'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since November 25, 2011. It is likely that your system is
      already no longer affected by this issue." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-31" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=343399" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=386273" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=388431" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-31." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "sys-libs/pam", unaffected: make_list( "ge 1.1.5" ), vulnerable: make_list( "lt 1.1.5" ) ) ) != NULL){
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

