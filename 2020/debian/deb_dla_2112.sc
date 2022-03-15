if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892112" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-17626" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-21 04:00:06 +0000 (Fri, 21 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for python-reportlab (DLA-2112-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2112-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942763" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-reportlab'
  package(s) announced via the DLA-2112-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that ReportLab, a Python library to create PDF documents,
did not properly parse color strings, allowing an attacker to execute
arbitrary code through a crafted input document." );
	script_tag( name: "affected", value: "'python-reportlab' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.1.8-3+deb8u2.

We recommend that you upgrade your python-reportlab packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-renderpm", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-renderpm-dbg", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-reportlab", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-reportlab-accel", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-reportlab-accel-dbg", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-reportlab-doc", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-renderpm", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-renderpm-dbg", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-reportlab", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-reportlab-accel", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-reportlab-accel-dbg", ver: "3.1.8-3+deb8u2", rls: "DEB8" ) )){
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

