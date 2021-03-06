if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703871" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_cve_id( "CVE-2017-5637" );
	script_name( "Debian Security Advisory DSA 3871-1 (zookeeper - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-01 00:00:00 +0200 (Thu, 01 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3871.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "zookeeper on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 3.4.5+dfsg-2+deb8u2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your zookeeper packages." );
	script_tag( name: "summary", value: "It was discovered that Zookeeper, a service for maintaining
configuration information, didn't restrict access to the computationally
expensive wchp/wchc commands which could result in denial of service by
elevated CPU consumption.

This update disables those two commands by default. The new
configuration option 4lw.commands.whitelist
can be used to whitelist
commands selectively (and the full set of commands can be restored
with '*')" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libzookeeper-java", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzookeeper-java-doc", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzookeeper-mt-dev", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzookeeper-mt2", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzookeeper-st-dev", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzookeeper-st2", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzookeeper2", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-zookeeper", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zookeeper", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zookeeper-bin", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zookeeperd", ver: "3.4.5+dfsg-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

