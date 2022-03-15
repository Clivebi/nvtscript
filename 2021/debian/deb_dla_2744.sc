if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892744" );
	script_version( "2021-08-17T08:10:55+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 08:10:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-17 03:00:11 +0000 (Tue, 17 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for usermode (DLA-2744-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2744-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2744-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/991808" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'usermode'
  package(s) announced via the DLA-2744-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update is merely a rebuild of the usermode package, which are
a set of graphical tools for certain user account management tasks,
fixing two issues:

a) the versioning issue as wheezy (Debian 7) had a greater version
than jessie (Debian 8) and stretch (Debian 9), thereby causing
upgrade issues.
b) the package now Depends and Build-Depends on the newer
libuser1-dev (>= 1:0.62~dfsg-0.1) to ensure the latest
version of libuser is used (which was a security fix)." );
	script_tag( name: "affected", value: "'usermode' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.109-1+deb9u1.

We recommend that you upgrade your usermode packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "usermode", ver: "1.109-1+deb9u1", rls: "DEB9" ) )){
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

