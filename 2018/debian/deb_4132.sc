if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704132" );
	script_version( "2021-06-18T02:36:51+0000" );
	script_cve_id( "CVE-2017-13194" );
	script_name( "Debian Security Advisory DSA 4132-1 (libvpx - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:36:51 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-04 00:00:00 +0100 (Sun, 04 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-24 00:15:00 +0000 (Fri, 24 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4132.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "libvpx on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.3.0-3+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.6.1-3+deb9u1.

We recommend that you upgrade your libvpx packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libvpx" );
	script_tag( name: "summary", value: "It was discovered that incorrect validation of frame widths in the libvpx
multimedia library may result in denial of service and potentially the
execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvpx-dev", ver: "1.3.0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx-doc", ver: "1.3.0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx1", ver: "1.3.0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx1-dbg", ver: "1.3.0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vpx-tools", ver: "1.3.0-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx-dev", ver: "1.6.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx-doc", ver: "1.6.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx4", ver: "1.6.1-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vpx-tools", ver: "1.6.1-3+deb9u1", rls: "DEB9" ) )){
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

