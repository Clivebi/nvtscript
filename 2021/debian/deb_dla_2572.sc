if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892572" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-0326" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 00:15:00 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-02-21 04:00:14 +0000 (Sun, 21 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for wpa (DLA-2572-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00033.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2572-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2572-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpa'
  package(s) announced via the DLA-2572-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in wpa, a set of tools to support WPA and WPA2
(IEEE 802.11i).
Missing validation of data can result in a buffer over-write, which might
lead to a DoS of the wpa_supplicant process or potentially arbitrary code
execution.

On request, together with this upload support for WPA-EAP-SUITE-B(-192)
has been enabled." );
	script_tag( name: "affected", value: "'wpa' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2:2.4-1+deb9u8.

We recommend that you upgrade your wpa packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "hostapd", ver: "2:2.4-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wpagui", ver: "2:2.4-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wpasupplicant", ver: "2:2.4-1+deb9u8", rls: "DEB9" ) )){
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

