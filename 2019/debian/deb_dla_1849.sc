if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891849" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-13132" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-09 02:00:08 +0000 (Tue, 09 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for zeromq3 (DLA-1849-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1849-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zeromq3'
  package(s) announced via the DLA-1849-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Fang-Pen Lin discovered a stack-based buffer-overflow flaw in ZeroMQ, a
lightweight messaging kernel library. A remote, unauthenticated client
connecting to an application using the libzmq library, running with a
socket listening with CURVE encryption/authentication enabled, can take
advantage of this flaw to cause a denial of service or the execution of
arbitrary code." );
	script_tag( name: "affected", value: "'zeromq3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4.0.5+dfsg-2+deb8u2.

We recommend that you upgrade your zeromq3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libzmq3", ver: "4.0.5+dfsg-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzmq3-dbg", ver: "4.0.5+dfsg-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzmq3-dev", ver: "4.0.5+dfsg-2+deb8u2", rls: "DEB8" ) )){
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

