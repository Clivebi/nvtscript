if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891867" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-11555", "CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-15 22:29:00 +0000 (Wed, 15 May 2019)" );
	script_tag( name: "creation_date", value: "2019-08-01 02:00:14 +0000 (Thu, 01 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for wpa (DLA-1867-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1867-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/927463" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpa'
  package(s) announced via the DLA-1867-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in WPA supplicant / hostapd. Some
of them could only partially be mitigated, please read below for details.

CVE-2019-9495

Cache-based side-channel attack against the EAP-pwd implementation:
an attacker able to run unprivileged code on the target machine
(including for example javascript code in a browser on a smartphone)
during the handshake could deduce enough information to discover the
password in a dictionary attack.

This issue has only very partially been mitigated against by reducing
measurable timing differences during private key operations. More
work is required to fully mitigate this vulnerability.

CVE-2019-9497

Reflection attack against EAP-pwd server implementation: a lack of
validation of received scalar and elements value in the
EAP-pwd-Commit messages could have resulted in attacks that would
have been able to complete EAP-pwd authentication exchange without
the attacker having to know the password. This did not result in the
attacker being able to derive the session key, complete the following
key exchange and access the network.

CVE-2019-9498

EAP-pwd server missing commit validation for scalar/element: hostapd
didn't validate values received in the EAP-pwd-Commit message, so an
attacker could have used a specially crafted commit message to
manipulate the exchange in order for hostapd to derive a session key
from a limited set of possible values. This could have resulted in an
attacker being able to complete authentication and gain access to the
network.

This issue could only partially be mitigated.

CVE-2019-9499

EAP-pwd peer missing commit validation for scalar/element:
wpa_supplicant didn't validate values received in the EAP-pwd-Commit
message, so an attacker could have used a specially crafted commit
message to manipulate the exchange in order for wpa_supplicant to
derive a session key from a limited set of possible values. This
could have resulted in an attacker being able to complete
authentication and operate as a rogue AP.

This issue could only partially be mitigated.

CVE-2019-11555

The EAP-pwd implementation did't properly validate fragmentation
reassembly state when receiving an unexpected fragment. This could
have lead to a process crash due to a NULL pointer dereference.

An attacker in radio range of a station or access point with EAP-pwd
support could cause a crash of the relevant process (wpa_supplicant
or hostapd), ensuring a denial of service." );
	script_tag( name: "affected", value: "'wpa' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.3-1+deb8u8.

We recommend that you upgrade your wpa packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "hostapd", ver: "2.3-1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wpagui", ver: "2.3-1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wpasupplicant", ver: "2.3-1+deb8u8", rls: "DEB8" ) )){
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

