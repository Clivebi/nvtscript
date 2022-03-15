if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892674" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_cve_id( "CVE-2021-25217" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-09 16:47:00 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-04 03:00:08 +0000 (Fri, 04 Jun 2021)" );
	script_name( "Debian LTS: Security Advisory for isc-dhcp (DLA-2674-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/06/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2674-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2674-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/989157" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'isc-dhcp'
  package(s) announced via the DLA-2674-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jon Franklin and Pawel Wieczorkiewicz found an issue in the ISC DHCP
client and server when parsing lease information, which could lead to
denial of service via application crash." );
	script_tag( name: "affected", value: "'isc-dhcp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
4.3.5-3+deb9u2.

We recommend that you upgrade your isc-dhcp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.3.5-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-client-ddns", ver: "4.3.5-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.3.5-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.3.5-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.3.5-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.3.5-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.3.5-3+deb9u2", rls: "DEB9" ) )){
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

