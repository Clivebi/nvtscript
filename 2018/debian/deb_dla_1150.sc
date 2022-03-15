if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891150" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13084", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088" );
	script_name( "Debian LTS: Security Advisory for wpa (DLA-1150-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "wpa on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.0-3+deb7u5. Note that the latter two vulnerabilities (CVE-2017-13087
and CVE-2017-13088) were mistakenly marked as fixed in the changelog
whereas they simply did not apply to the 1.0 version of the WPA source
code, which doesn't implement WNM sleep mode responses.

We recommend that you upgrade your wpa packages." );
	script_tag( name: "summary", value: "A vulnerability was found in how WPA code can be triggered to
reconfigure WPA/WPA2/RSN keys (TK, GTK, or IGTK) by replaying a specific
frame that is used to manage the keys. Such reinstallation of the
encryption key can result in two different types of vulnerabilities:
disabling replay protection and significantly reducing the security of
encryption to the point of allowing frames to be decrypted or some parts
of the keys to be determined by an attacker depending on which cipher is
used.

Those issues are commonly known under the 'KRACK' appelation. According
to US-CERT, 'the impact of exploiting these vulnerabilities includes
decryption, packet replay, TCP connection hijacking, HTTP content
injection, and others.'

CVE-2017-13077

Reinstallation of the pairwise encryption key (PTK-TK) in the
4-way handshake.

CVE-2017-13078

Reinstallation of the group key (GTK) in the 4-way handshake.

CVE-2017-13079

Reinstallation of the integrity group key (IGTK) in the 4-way
handshake.

CVE-2017-13080

Reinstallation of the group key (GTK) in the group key handshake.

CVE-2017-13081

Reinstallation of the integrity group key (IGTK) in the group key
handshake.

CVE-2017-13082

Accepting a retransmitted Fast BSS Transition (FT) Reassociation
Request and reinstalling the pairwise encryption key (PTK-TK)
while processing it.

CVE-2017-13084

Reinstallation of the STK key in the PeerKey handshake.

CVE-2017-13086

reinstallation of the Tunneled Direct-Link Setup (TDLS) PeerKey
(TPK) key in the TDLS handshake.

CVE-2017-13087

reinstallation of the group key (GTK) when processing a Wireless
Network Management (WNM) Sleep Mode Response frame.

CVE-2017-13088

reinstallation of the integrity group key (IGTK) when processing a
Wireless Network Management (WNM) Sleep Mode Response frame." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "hostapd", ver: "1.0-3+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wpagui", ver: "1.0-3+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wpasupplicant", ver: "1.0-3+deb7u5", rls: "DEB7" ) )){
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

