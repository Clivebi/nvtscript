if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891313" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-5732", "CVE-2018-5733" );
	script_name( "Debian LTS: Security Advisory for isc-dhcp (DLA-1313-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-09 21:14:00 +0000 (Thu, 09 Jan 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "isc-dhcp on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.2.2.dfsg.1-5+deb70u9.

We recommend that you upgrade your isc-dhcp packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the ISC DHCP client,
relay and server. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2018-5732

Felix Wilhelm of the Google Security Team discovered that the DHCP
client is prone to an out-of-bound memory access vulnerability when
processing specially constructed DHCP options responses, resulting
in potential execution of arbitrary code by a malicious DHCP server.

CVE-2018-5733

Felix Wilhelm of the Google Security Team discovered that the DHCP
server does not properly handle reference counting when processing
client requests. A malicious client can take advantage of this flaw
to cause a denial of service (dhcpd crash) by sending large amounts
of traffic." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.2.2.dfsg.1-5+deb70u9", rls: "DEB7" ) )){
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

