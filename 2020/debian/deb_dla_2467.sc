if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892467" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2018-19787", "CVE-2020-27783" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-26 21:15:00 +0000 (Thu, 26 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-27 04:00:09 +0000 (Fri, 27 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for lxml (DLA-2467-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00044.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2467-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lxml'
  package(s) announced via the DLA-2467-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2018-19787

It was discovered that there was a XSS injection vulnerability in
the LXML HTML/XSS manipulation library for Python.

CVE-2020-27783

javascript escaping through the <noscript> and <style> combinations." );
	script_tag( name: "affected", value: "'lxml' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
3.7.1-1+deb9u1.

We recommend that you upgrade your lxml packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-lxml", ver: "3.7.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-lxml-dbg", ver: "3.7.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-lxml-doc", ver: "3.7.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-lxml", ver: "3.7.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-lxml-dbg", ver: "3.7.1-1+deb9u1", rls: "DEB9" ) )){
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

