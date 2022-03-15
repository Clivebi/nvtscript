if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704088" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2017-1000422", "CVE-2017-6312", "CVE-2017-6313", "CVE-2017-6314" );
	script_name( "Debian Security Advisory DSA 4088-1 (gdk-pixbuf - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-15 00:00:00 +0100 (Mon, 15 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-02 16:35:00 +0000 (Thu, 02 May 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4088.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "gdk-pixbuf on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 2.31.1-2+deb8u7.

For the stable distribution (stretch), this problem has been fixed in
version 2.36.5-2+deb9u2. In addition this update provides fixes for
CVE-2017-6312, CVE-2017-6313 and CVE-2017-6314
.

We recommend that you upgrade your gdk-pixbuf packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/gdk-pixbuf" );
	script_tag( name: "summary", value: "It was discovered that multiple integer overflows in the GIF image loader
in the GDK Pixbuf library may result in denial of service and potentially
the execution of arbitrary code if a malformed image file is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gdkpixbuf-2.0", ver: "2.36.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.36.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-common", ver: "2.36.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-dev", ver: "2.36.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-doc", ver: "2.36.5-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gdkpixbuf-2.0", ver: "2.31.1-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.31.1-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0-dbg", ver: "2.31.1-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-common", ver: "2.31.1-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-dev", ver: "2.31.1-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-doc", ver: "2.31.1-2+deb8u7", rls: "DEB8" ) )){
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

