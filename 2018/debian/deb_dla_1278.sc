if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891278" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-1000041" );
	script_name( "Debian LTS: Security Advisory for librsvg (DLA-1278-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/02/msg00013.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "librsvg on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this issue has been fixed in librsvg version
2.36.1-2+deb7u3.

We recommend that you upgrade your librsvg packages." );
	script_tag( name: "summary", value: "It was discovered that there was an input validation vulnerability in
the librsvg renderer library that could result in data being leaked to
remote attackers via a specially-crafted file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-rsvg-2.0", ver: "2.36.1-2+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librsvg2-2", ver: "2.36.1-2+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librsvg2-bin", ver: "2.36.1-2+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librsvg2-common", ver: "2.36.1-2+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librsvg2-dbg", ver: "2.36.1-2+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librsvg2-dev", ver: "2.36.1-2+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librsvg2-doc", ver: "2.36.1-2+deb7u3", rls: "DEB7" ) )){
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

