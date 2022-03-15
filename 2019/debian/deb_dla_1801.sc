if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891801" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-0201" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-05-25 02:00:07 +0000 (Sat, 25 May 2019)" );
	script_name( "Debian LTS: Security Advisory for zookeeper (DLA-1801-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00033.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1801-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/929283" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zookeeper'
  package(s) announced via the DLA-1801-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an information disclosure
vulnerability in zookeeper, a distributed co-ordination server.
Users who were not authorised to read data were able to view the
access control list." );
	script_tag( name: "affected", value: "'zookeeper' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in zookeeper version
3.4.9-3+deb8u2.

We recommend that you upgrade your zookeeper packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java-doc", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt-dev", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt2", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st-dev", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st2", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper2", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-zookeeper", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper-bin", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeperd", ver: "3.4.9-3+deb8u2", rls: "DEB8" ) )){
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
