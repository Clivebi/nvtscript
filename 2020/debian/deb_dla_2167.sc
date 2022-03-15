if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892167" );
	script_version( "2020-04-02T03:00:06+0000" );
	script_cve_id( "CVE-2020-6817" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-02 03:00:06 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-02 03:00:06 +0000 (Thu, 02 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for python-bleach (DLA-2167-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2167-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/955388" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-bleach'
  package(s) announced via the DLA-2167-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in python-bleach, a whitelist-based
HTML-sanitizing library. Calls to bleach.clean with an allowed tag with
an allowed style attribute are vulnerable to a regular expression denial
of service (ReDoS)." );
	script_tag( name: "affected", value: "'python-bleach' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.4-1+deb8u1.

We recommend that you upgrade your python-bleach packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-bleach", ver: "1.4-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-bleach-doc", ver: "1.4-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-bleach", ver: "1.4-1+deb8u1", rls: "DEB8" ) )){
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

