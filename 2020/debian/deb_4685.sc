if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704685" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2020-3810" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-05-15 03:00:06 +0000 (Fri, 15 May 2020)" );
	script_name( "Debian: Security Advisory for apt (DSA-4685-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4685.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4685-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apt'
  package(s) announced via the DSA-4685-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Shuaibing Lu discovered that missing input validation in the ar/tar
implementations of APT, the high level package manager, could result in
denial of service when processing specially crafted deb files." );
	script_tag( name: "affected", value: "'apt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1.4.10.

For the stable distribution (buster), this problem has been fixed in
version 1.8.2.1.

We recommend that you upgrade your apt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "apt", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apt-doc", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apt-transport-https", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apt-utils", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-inst2.0", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-pkg-dev", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-pkg-doc", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-pkg5.0", ver: "1.8.2.1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apt", ver: "1.4.10", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apt-doc", ver: "1.4.10", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apt-transport-https", ver: "1.4.10", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apt-utils", ver: "1.4.10", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-inst2.0", ver: "1.4.10", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-pkg-dev", ver: "1.4.10", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-pkg-doc", ver: "1.4.10", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapt-pkg5.0", ver: "1.4.10", rls: "DEB9" ) )){
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

