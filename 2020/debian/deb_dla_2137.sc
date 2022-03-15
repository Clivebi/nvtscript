if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892137" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-10232" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-17 06:15:00 +0000 (Sun, 17 May 2020)" );
	script_tag( name: "creation_date", value: "2020-03-18 10:44:41 +0000 (Wed, 18 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for sleuthkit (DLA-2137-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2137-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sleuthkit'
  package(s) announced via the DLA-2137-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In version 4.8.0 and earlier of The Sleuth Kit (TSK), there is
a stack buffer overflow vulnerability in the YAFFS file timestamp
parsing logic in yaffsfs_istat() in fs/yaffs.c." );
	script_tag( name: "affected", value: "'sleuthkit' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4.1.3-4+deb8u2.

We recommend that you upgrade your sleuthkit packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtsk-dev", ver: "4.1.3-4+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtsk10", ver: "4.1.3-4+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sleuthkit", ver: "4.1.3-4+deb8u2", rls: "DEB8" ) )){
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

