if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891981" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-14866" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-10 14:27:00 +0000 (Fri, 10 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-11-06 03:00:20 +0000 (Wed, 06 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for cpio (DLA-1981-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1981-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/941412" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cpio'
  package(s) announced via the DLA-1981-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in the cpio package.

CVE-2019-14866

It is possible for an attacker to create a file so when
backed up with cpio can generate arbitrary files in the
resulting tar archive. When the backup is restored the
file is then created with arbitrary permissions." );
	script_tag( name: "affected", value: "'cpio' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.11+dfsg-4.1+deb8u2.

We recommend that you upgrade your cpio packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cpio", ver: "2.11+dfsg-4.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cpio-win32", ver: "2.11+dfsg-4.1+deb8u2", rls: "DEB8" ) )){
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

