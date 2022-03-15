if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891730" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:42:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-03-25 23:00:00 +0100 (Mon, 25 Mar 2019)" );
	script_name( "Debian LTS: Security Advisory for libssh2 (DLA-1730-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00032.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1730-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libssh2'
  package(s) announced via the DLA-1730-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have recently been discovered in libssh2, a
client-side C library implementing the SSH2 protocol

CVE-2019-3855

An integer overflow flaw which could have lead to an out of bounds
write was discovered in libssh2 in the way packets were read from the
server. A remote attacker who compromised an SSH server could have
been able to execute code on the client system when a user connected
to the server.

CVE-2019-3856

An integer overflow flaw, which could have lead to an out of bounds
write, was discovered in libssh2 in the way keyboard prompt requests
were parsed. A remote attacker who compromised an SSH server could have
been able to execute code on the client system when a user connected
to the server.

CVE-2019-3857

An integer overflow flaw which could have lead to an out of bounds
write was discovered in libssh2 in the way SSH_MSG_CHANNEL_REQUEST
packets with an exit signal were parsed. A remote attacker who
compromises an SSH server could have been able to execute code on the
client system when a user connected to the server.

CVE-2019-3858

An out of bounds read flaw was discovered in libssh2 when a specially
crafted SFTP packet was received from the server. A remote attacker
who compromised an SSH server could have been able to cause a Denial
of Service or read data in the client memory.

CVE-2019-3859

An out of bounds read flaw was discovered in libssh2's
_libssh2_packet_require and _libssh2_packet_requirev functions. A
remote attacker who compromised an SSH server could have be able to
cause a Denial of Service or read data in the client memory.

CVE-2019-3860

An out of bounds read flaw was discovered in libssh2 in the way SFTP
packets with empty payloads were parsed. A remote attacker who
compromised an SSH server could have be able to cause a Denial of
Service or read data in the client memory.

CVE-2019-3861

An out of bounds read flaw was discovered in libssh2 in the way SSH
packets with a padding length value greater than the packet length
were parsed. A remote attacker who compromised a SSH server could
have been able to cause a Denial of Service or read data in the
client memory.

CVE-2019-3862

An out of bounds read flaw was discovered in libssh2 in the way
SSH_MSG_CHANNEL_REQUEST packets with an exit status message and no
payload were parsed. A remote attacker who compromised an SSH server
could have been able to cause a Denial of Service or read data in the
client memory.

CVE-2019-3863

A server could have sent multiple keyboard interactive response
messages whose total length were greater than unsigned char max
characters. This value was used as an index to copy memory causing
an out of bounds memory write error." );
	script_tag( name: "affected", value: "'libssh2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.4.3-4.1+deb8u2.

We recommend that you upgrade your libssh2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssh2-1", ver: "1.4.3-4.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssh2-1-dbg", ver: "1.4.3-4.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssh2-1-dev", ver: "1.4.3-4.1+deb8u2", rls: "DEB8" ) )){
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

