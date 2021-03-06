if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72521" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5374", "CVE-2012-3410" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-22 08:43:44 -0400 (Mon, 22 Oct 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201210-05 (bash)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Two vulnerabilities have been found in Bash, the worst of which may
    allow execution of arbitrary code." );
	script_tag( name: "solution", value: "All Bash users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.2_p37'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201210-05" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=251319" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=431850" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201210-05." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-shells/bash", unaffected: make_list( "ge 4.2_p37" ), vulnerable: make_list( "lt 4.2_p37" ) ) ) != NULL){
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

