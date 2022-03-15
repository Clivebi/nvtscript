if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892341" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-10188" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-08-25 03:00:07 +0000 (Tue, 25 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for inetutils (DLA-2341-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2341-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/956084" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'inetutils'
  package(s) announced via the DLA-2341-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In inetutils-telnetd, an implementation of a telnet daemon,
arbitrary remote code execution might have been possible via
short writes or urgent data." );
	script_tag( name: "affected", value: "'inetutils' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2:1.9.4-2+deb9u1.

We recommend that you upgrade your inetutils-telnetd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "inetutils-ftp", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-ftpd", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-inetd", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-ping", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-syslogd", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-talk", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-talkd", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-telnet", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-telnetd", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-tools", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inetutils-traceroute", ver: "2:1.9.4-2+deb9u1", rls: "DEB9" ) )){
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

