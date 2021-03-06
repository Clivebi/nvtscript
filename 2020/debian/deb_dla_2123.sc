if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892123" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-9274" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-22 06:15:00 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-02-28 04:00:12 +0000 (Fri, 28 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for pure-ftpd (DLA-2123-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2123-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/925666" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pure-ftpd'
  package(s) announced via the DLA-2123-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An uninitialized pointer vulnerability was discovered in pure-ftpd, a
secure and efficient FTP server, which could result in an out-of-bounds
memory read and potential information disclosure." );
	script_tag( name: "affected", value: "'pure-ftpd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.0.36-3.2+deb8u1.

We recommend that you upgrade your pure-ftpd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pure-ftpd", ver: "1.0.36-3.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pure-ftpd-common", ver: "1.0.36-3.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pure-ftpd-ldap", ver: "1.0.36-3.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pure-ftpd-mysql", ver: "1.0.36-3.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pure-ftpd-postgresql", ver: "1.0.36-3.2+deb8u1", rls: "DEB8" ) )){
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

