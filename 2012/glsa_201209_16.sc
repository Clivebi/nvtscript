if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72450" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-0805" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-03 11:11:28 -0400 (Wed, 03 Oct 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201209-16 (sqlalchemy)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "An input sanitation flaw in SQLAlchemy allows remote attacker to
    conduct SQL injection." );
	script_tag( name: "solution", value: "All SQLAlchemy users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-python/sqlalchemy-0.7.4'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-16" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=407437" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201209-16." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-python/sqlalchemy", unaffected: make_list( "ge 0.7.4" ), vulnerable: make_list( "lt 0.7.4" ) ) ) != NULL){
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

