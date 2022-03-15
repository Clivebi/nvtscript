if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890986" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-5637" );
	script_name( "Debian LTS: Security Advisory for zookeeper (DLA-986-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "zookeeper on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.4.5+dfsg-2+deb7u1.

We recommend that you upgrade your zookeeper packages." );
	script_tag( name: "summary", value: "It was discovered that Zookeeper, a service for maintaining
configuration information, didn't restrict access to the computationally
expensive wchp/wchc commands which could result in denial of service by
elevated CPU consumption.

This update disables those two commands by default. The new
configuration option '4lw.commands.whitelist' can be used to whitelist
commands selectively (and the full set of commands can be restored
with '*')" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java-doc", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt-dev", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt2", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st-dev", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st2", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper2", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-zookeeper", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper-bin", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeperd", ver: "3.4.5+dfsg-2+deb7u1", rls: "DEB7" ) )){
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

