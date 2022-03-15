if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704809" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-27351" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-14 19:56:00 +0000 (Mon, 14 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-11 04:00:05 +0000 (Fri, 11 Dec 2020)" );
	script_name( "Debian: Security Advisory for python-apt (DSA-4809-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4809.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4809-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-apt'
  package(s) announced via the DSA-4809-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Various memory and file descriptor leaks were discovered in the Python
interface to the APT package management runtime library, which could
result in denial of service." );
	script_tag( name: "affected", value: "'python-apt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.8.4.2.

We recommend that you upgrade your python-apt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-apt", ver: "1.8.4.2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-common", ver: "1.8.4.2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-dbg", ver: "1.8.4.2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-dev", ver: "1.8.4.2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-doc", ver: "1.8.4.2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-apt", ver: "1.8.4.2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-apt-dbg", ver: "1.8.4.2", rls: "DEB10" ) )){
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

