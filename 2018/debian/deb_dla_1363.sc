if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891363" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-10194" );
	script_name( "Debian LTS: Security Advisory for ghostscript (DLA-1363-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-27 00:00:00 +0200 (Fri, 27 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-24 16:21:00 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/04/msg00028.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ghostscript on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
9.05~dfsg-6.3+deb7u8.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "summary", value: "It was discovered that the set_text_distance function in
base/gdevpdts.c in the pdfwrite component in Ghostscript does not
prevent overflows in text-positioning calculation, which allows remote
attackers to cause a denial of service (application crash) or possibly
have unspecified other impact via a crafted PDF document." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-cups", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.05~dfsg-6.3+deb7u8", rls: "DEB7" ) )){
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

