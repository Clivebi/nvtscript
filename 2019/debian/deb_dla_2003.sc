if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892003" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2016-2774" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-08 17:17:00 +0000 (Wed, 08 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:50:18 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for isc-dhcp (DLA-2003-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2003-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'isc-dhcp'
  package(s) announced via the DLA-2003-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in isc-dhcp, a server for automatic IP address
assignment.

The number of simultaneous open TCP connections to OMAPI port of the
server has to be limited to 200 in order to avoid a denial of service." );
	script_tag( name: "affected", value: "'isc-dhcp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4.3.1-6+deb8u4.

We recommend that you upgrade your isc-dhcp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-dbg", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.3.1-6+deb8u4", rls: "DEB8" ) )){
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

