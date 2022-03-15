if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892315" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-12695" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 00:15:00 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-17 13:21:54 +0000 (Mon, 17 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for gupnp (DLA-2315-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2315-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gupnp'
  package(s) announced via the DLA-2315-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Yunus Cadirci found an issue in the SUBSCRIBE method of UPnP, a
network protocol for devices to automatically discover and communicate
with each other. Insuficient checks on this method allowed attackers
to use vulnerable UPnP services for DoS attacks or possibly to bypass
firewalls." );
	script_tag( name: "affected", value: "'gupnp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.0.1-1+deb9u1.

We recommend that you upgrade your gupnp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gupnp-1.0", ver: "1.0.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgupnp-1.0-4", ver: "1.0.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgupnp-1.0-dev", ver: "1.0.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgupnp-doc", ver: "1.0.1-1+deb9u1", rls: "DEB9" ) )){
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

