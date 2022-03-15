if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892276" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-12108", "CVE-2020-15011" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 16:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-07-17 12:33:14 +0000 (Fri, 17 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for mailman (DLA-2276-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2276-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mailman'
  package(s) announced via the DLA-2276-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following CVEs were reported against src:mailman.

CVE-2020-12108

/options/mailman in GNU Mailman before 2.1.31 allows Arbitrary
Content Injection.

CVE-2020-15011

GNU Mailman before 2.1.33 allows arbitrary content injection via
the Cgi/private.py private archive login page." );
	script_tag( name: "affected", value: "'mailman' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1:2.1.23-1+deb9u6.

We recommend that you upgrade your mailman packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mailman", ver: "1:2.1.23-1+deb9u6", rls: "DEB9" ) )){
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
exit( 0 );

