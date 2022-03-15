if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704499" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-10216" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 18:17:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-08-13 02:00:06 +0000 (Tue, 13 Aug 2019)" );
	script_name( "Debian Security Advisory DSA 4499-1 (ghostscript - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4499.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4499-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the DSA-4499-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Netanel reported that the .buildfont1 procedure in Ghostscript, the GPL
PostScript/PDF interpreter, does not properly restrict privileged calls,
which could result in bypass of file system restrictions of the dSAFER
sandbox." );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 9.26a~dfsg-0+deb9u4.

For the stable distribution (buster), this problem has been fixed in
version 9.27~dfsg-2+deb10u1.

We recommend that you upgrade your ghostscript packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.26a~dfsg-0+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.26a~dfsg-0+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.26a~dfsg-0+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.26a~dfsg-0+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.26a~dfsg-0+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.26a~dfsg-0+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.26a~dfsg-0+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript", ver: "9.27~dfsg-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-dbg", ver: "9.27~dfsg-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-doc", ver: "9.27~dfsg-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ghostscript-x", ver: "9.27~dfsg-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs-dev", ver: "9.27~dfsg-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9", ver: "9.27~dfsg-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgs9-common", ver: "9.27~dfsg-2+deb10u1", rls: "DEB10" ) )){
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

