if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72519" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:H/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1595" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-22 08:43:43 -0400 (Mon, 22 Oct 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201210-03 (rdesktop)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "A vulnerability which allows a remote attacking server to read or
    overwrite arbitrary files has been found in rdesktop." );
	script_tag( name: "solution", value: "All rdesktop users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/rdesktop-1.7.0'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201210-03" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=364191" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201210-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-misc/rdesktop", unaffected: make_list( "ge 1.7.0" ), vulnerable: make_list( "lt 1.7.0" ) ) ) != NULL){
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

