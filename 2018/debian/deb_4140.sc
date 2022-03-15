if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704140" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2018-5146" );
	script_name( "Debian Security Advisory DSA 4140-1 (libvorbis - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-16 00:00:00 +0100 (Fri, 16 Mar 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-11 19:33:00 +0000 (Mon, 11 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4140.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libvorbis on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.3.4-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.3.5-4+deb9u2.

We recommend that you upgrade your libvorbis packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libvorbis" );
	script_tag( name: "summary", value: "Richard Zhu discovered that an out-of-bounds memory write in the
codebook parsing code of the Libvorbis multimedia library could result
in the execution of arbitrary code if a malformed Vorbis file is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvorbis-dbg", ver: "1.3.5-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbis-dev", ver: "1.3.5-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbis0a", ver: "1.3.5-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbisenc2", ver: "1.3.5-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbisfile3", ver: "1.3.5-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbis-dbg", ver: "1.3.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbis-dev", ver: "1.3.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbis0a", ver: "1.3.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbisenc2", ver: "1.3.4-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvorbisfile3", ver: "1.3.4-2+deb8u1", rls: "DEB8" ) )){
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

