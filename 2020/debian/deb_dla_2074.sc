if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892074" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2019-15795", "CVE-2019-15796" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-08 18:23:00 +0000 (Wed, 08 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-01-24 04:00:10 +0000 (Fri, 24 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for python-apt (DLA-2074-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00020.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2074-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/944696" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-apt'
  package(s) announced via the DLA-2074-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in python-apt, a python interface to libapt-pkg.

CVE-2019-15795

It was discovered that python-apt would still use MD5 hashes to validate
certain downloaded packages. If a remote attacker were able to perform a
man-in-the-middle attack, this flaw could potentially be used to install
altered packages.

CVE-2019-15796

It was discovered that python-apt could install packages from untrusted
repositories, contrary to expectations." );
	script_tag( name: "affected", value: "'python-apt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.9.3.13.

We recommend that you upgrade your python-apt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-apt", ver: "0.9.3.13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-common", ver: "0.9.3.13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-dbg", ver: "0.9.3.13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-dev", ver: "0.9.3.13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-apt-doc", ver: "0.9.3.13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-apt", ver: "0.9.3.13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-apt-dbg", ver: "0.9.3.13", rls: "DEB8" ) )){
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

