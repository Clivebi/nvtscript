if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892224" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2015-8872", "CVE-2016-4804" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-30 18:15:00 +0000 (Sat, 30 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-31 03:00:10 +0000 (Sun, 31 May 2020)" );
	script_name( "Debian LTS: Security Advisory for dosfstools (DLA-2224-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2224-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dosfstools'
  package(s) announced via the DLA-2224-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was both an invalid memory and heap overflow
vulnerability in dosfstools, a collection of utilities for making and
checking MS-DOS FAT filesystems." );
	script_tag( name: "affected", value: "'dosfstools' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.0.27-1+deb8u1.

We recommend that you upgrade your dosfstools packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dosfstools", ver: "3.0.27-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dosfstools-dbg", ver: "3.0.27-1+deb8u1", rls: "DEB8" ) )){
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

