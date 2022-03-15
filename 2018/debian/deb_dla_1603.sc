if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891603" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2017-15377", "CVE-2017-7177", "CVE-2018-6794" );
	script_name( "Debian LTS: Security Advisory for suricata (DLA-1603-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-05 00:00:00 +0100 (Wed, 05 Dec 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 14:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/12/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "suricata on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.0.7-2+deb8u3.

We recommend that you upgrade your suricata packages." );
	script_tag( name: "summary", value: "Several issues were found in suricata, an intrusion detection and
prevention tool.

CVE-2017-7177

Suricata has an IPv4 defragmentation evasion issue caused by lack
of a check for the IP protocol during fragment matching.

CVE-2017-15377

It was possible to trigger lots of redundant checks on the content
of crafted network traffic with a certain signature, because of
DetectEngineContentInspection in detect-engine-content-inspection.c.
The search engine doesn't stop when it should after no match is
found. Instead, it stops only upon reaching inspection-recursion-
limit (3000 by default).

CVE-2018-6794

Suricata is prone to an HTTP detection bypass vulnerability in
detect.c and stream-tcp.c. If a malicious server breaks a normal
TCP flow and sends data before the 3-way handshake is complete,
then the data sent by the malicious server will be accepted by web
clients such as a web browser or Linux CLI utilities, but ignored
by Suricata IDS signatures. This mostly affects IDS signatures for
the HTTP protocol and TCP stream content. Signatures for TCP packets
will inspect such network traffic as usual.

TEMP-0856648-2BC2C9 (no CVE assigned yet)

Out of bounds read in app-layer-dns-common.c.
On a zero size A or AAAA record, 4 or 16 bytes would still be read." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "suricata", ver: "2.0.7-2+deb8u3", rls: "DEB8" ) )){
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

