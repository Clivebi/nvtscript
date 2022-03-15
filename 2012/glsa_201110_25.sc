if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70788" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2011-0418", "CVE-2011-1575" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201110-25 (Pure-FTPd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in Pure-FTPd allowing attackers
    to inject FTP commands or cause a Denial of Service." );
	script_tag( name: "solution", value: "All pure-ftpd users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-ftp/pure-ftpd-1.0.32'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since May 14, 2011. It is likely that your system is
already no
      longer affected by this issue." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-25" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=358375" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=365751" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201110-25." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-ftp/pure-ftpd", unaffected: make_list( "ge 1.0.32" ), vulnerable: make_list( "lt 1.0.32" ) ) ) != NULL){
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

