if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892450" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-26154" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-29 04:15:00 +0000 (Sun, 29 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-14 04:00:14 +0000 (Sat, 14 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for libproxy (DLA-2450-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00024.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2450-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/968366" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libproxy'
  package(s) announced via the DLA-2450-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Li Fei found that libproxy, a library for automatic proxy configuration
management, was vulnerable to a buffer overflow vulnerability when
receiving a large PAC file from a server without a Content-Length header
in the response." );
	script_tag( name: "affected", value: "'libproxy' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.4.14-2+deb9u2.

We recommend that you upgrade your libproxy packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libproxy-cil-dev", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy-dev", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy-tools", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy0.4-cil", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy1-plugin-gsettings", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy1-plugin-kconfig", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy1-plugin-mozjs", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy1-plugin-networkmanager", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy1-plugin-webkit", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libproxy1v5", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libproxy", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-libproxy", ver: "0.4.14-2+deb9u2", rls: "DEB9" ) )){
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

