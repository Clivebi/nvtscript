if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891687" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_cve_id( "CVE-2014-8145" );
	script_name( "Debian LTS: Security Advisory for sox (DLA-1687-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-02-25 00:00:00 +0100 (Mon, 25 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00034.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "sox on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
14.4.1-5+deb8u1.

We recommend that you upgrade your sox packages." );
	script_tag( name: "summary", value: "Mike Salvatore discovered that the fixes for these heap-based buffer
overflows had not been properly applied in the Debian package." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsox-dev", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-all", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-alsa", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-ao", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-base", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-mp3", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-oss", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox-fmt-pulse", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsox2", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sox", ver: "14.4.1-5+deb8u1", rls: "DEB8" ) )){
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

