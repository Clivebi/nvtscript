if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892231" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-12867" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-06-01 03:00:09 +0000 (Mon, 01 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for sane-backends (DLA-2231-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00036.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2231-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/961302" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sane-backends'
  package(s) announced via the DLA-2231-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Remote denial of service and several memory
management issues were fixed in the epson2 driver." );
	script_tag( name: "affected", value: "'sane-backends' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.0.24-8+deb8u3.

We recommend that you upgrade your sane-backends packages
if you are using the epson2 driver." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsane", ver: "1.0.24-8+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsane-common", ver: "1.0.24-8+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsane-dbg", ver: "1.0.24-8+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsane-dev", ver: "1.0.24-8+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sane-utils", ver: "1.0.24-8+deb8u3", rls: "DEB8" ) )){
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
