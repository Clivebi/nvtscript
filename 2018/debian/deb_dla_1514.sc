if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891514" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2018-17407" );
	script_name( "Debian LTS: Security Advisory for texlive-bin (DLA-1514-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-24 00:00:00 +0200 (Mon, 24 Sep 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-15 16:11:00 +0000 (Thu, 15 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00025.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "texlive-bin on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2014.20140926.35254-6+deb8u1.

We recommend that you upgrade your texlive-bin packages." );
	script_tag( name: "summary", value: "Nick Roessler from the University of Pennsylvania has found a buffer overflow
in texlive-bin, the executables for TexLive, the popular distribution of TeX
document production system.

This buffer overflow can be used for arbitrary code execution by crafting a
special type1 font (.pfb) and provide it to users running pdf(la)tex, dvips or
luatex in a way that the font is loaded." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libkpathsea-dev", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkpathsea6", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libptexenc-dev", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libptexenc1", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsynctex-dev", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsynctex1", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "luatex", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "texlive-binaries", ver: "2014.20140926.35254-6+deb8u1", rls: "DEB8" ) )){
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

