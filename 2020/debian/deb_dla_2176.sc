if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892176" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-10188" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-05-15 03:00:08 +0000 (Fri, 15 May 2020)" );
	script_name( "Debian LTS: Security Advisory for inetutils (DLA-2176-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00012.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2176-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/956084" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'inetutils'
  package(s) announced via the DLA-2176-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in the telnetd component of inetutils, a
collection of network utilities. Execution of arbitrary remote code was
possible through short writes or urgent data." );
	script_tag( name: "affected", value: "'inetutils' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2:1.9.2.39.3a460-3+deb8u1.

We recommend that you upgrade your inetutils packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "inetutils-ftp", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-ftpd", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-inetd", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-ping", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-syslogd", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-talk", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-talkd", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-telnet", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-telnetd", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-tools", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-traceroute", ver: "2:1.9.2.39.3a460-3+deb8u1", rls: "DEB8" ) )){
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

