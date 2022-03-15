if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71855" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2012-2451" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:34:52 -0400 (Thu, 30 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201208-05 (Config-IniFiles)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "An insecure temporary file usage has been reported in the Perl
    Config-IniFiles module, possibly allowing symlink attacks." );
	script_tag( name: "solution", value: "All users of the Perl Config-IniFiles module should upgrade to the
      latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-perl/Config-IniFiles-2.710.0'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201208-05" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=414485" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201208-05." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-perl/Config-IniFiles", unaffected: make_list( "ge 2.710.0" ), vulnerable: make_list( "lt 2.710.0" ) ) ) != NULL){
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

