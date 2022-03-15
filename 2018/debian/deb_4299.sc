if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704299" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-17407" );
	script_name( "Debian Security Advisory DSA 4299-1 (texlive-bin - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-21 00:00:00 +0200 (Fri, 21 Sep 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-15 16:11:00 +0000 (Thu, 15 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4299.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "texlive-bin on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2016.20160513.41080.dfsg-2+deb9u1.

We recommend that you upgrade your texlive-bin packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/texlive-bin" );
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
if(!isnull( res = isdpkgvuln( pkg: "libkpathsea-dev", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkpathsea6", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libptexenc-dev", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libptexenc1", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsynctex-dev", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsynctex1", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtexlua52", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtexlua52-dev", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtexluajit-dev", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtexluajit2", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "texlive-binaries", ver: "2016.20160513.41080.dfsg-2+deb9u1", rls: "DEB9" ) )){
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

