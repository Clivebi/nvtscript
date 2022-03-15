if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844315" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2020-2583", "CVE-2020-2590", "CVE-2020-2593", "CVE-2020-2601", "CVE-2020-2604", "CVE-2020-2654", "CVE-2020-2655", "CVE-2020-2659" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 20:48:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-01-29 04:00:24 +0000 (Wed, 29 Jan 2020)" );
	script_name( "Ubuntu: Security Advisory for openjdk-8 (USN-4257-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4257-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005300.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the USN-4257-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenJDK incorrectly handled exceptions during
deserialization in BeanContextSupport. An attacker could possibly use this
issue to cause a denial of service or other unspecified impact.
(CVE-2020-2583)

It was discovered that OpenJDK incorrectly validated properties of SASL
messages included in Kerberos GSSAPI. An unauthenticated remote attacker
with network access via Kerberos could possibly use this issue to insert,
modify or obtain sensitive information. (CVE-2020-2590)

It was discovered that OpenJDK incorrectly validated URLs. An attacker
could possibly use this issue to insert, edit or obtain sensitive
information. (CVE-2020-2593)

It was discovered that OpenJDK Security component still used MD5 algorithm.
A remote attacker could possibly use this issue to obtain sensitive
information. (CVE-2020-2601)

It was discovered that OpenJDK incorrectly handled the application of
serialization filters. An attacker could possibly use this issue to bypass the
intended filter during serialization. (CVE-2020-2604)

Bo Zhang and Long Kuan discovered that OpenJDK incorrectly handled X.509
certificates. An attacker could possibly use this issue to cause a denial
of service. (CVE-2020-2654)

Bengt Jonsson, Juraj Somorovsky, Kostis Sagonas, Paul Fiterau Brostean and
Robertdiscovered that OpenJDK incorrectly handled CertificateVerify
TLS handshake messages. A remote attacker could possibly use this issue to
insert, edit or obtain sensitive information. This issue only affected
OpenJDK 11. (CVE-2020-2655)

It was discovered that OpenJDK incorrectly enforced the limit of datagram
sockets that can be created by a code running within a Java sandbox. An
attacker could possibly use this issue to bypass the sandbox restrictions
causing a denial of service. This issue only affected OpenJDK 8.
(CVE-2020-2659)" );
	script_tag( name: "affected", value: "'openjdk-8' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.6+10-1ubuntu1~19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.6+10-1ubuntu1~19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.6+10-1ubuntu1~19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.6+10-1ubuntu1~19.10.1", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u242-b08-0ubuntu3~19.10", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u242-b08-0ubuntu3~19.10", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u242-b08-0ubuntu3~19.10", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u242-b08-0ubuntu3~19.10", rls: "UBUNTU19.10" ) )){
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
}
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.6+10-1ubuntu1~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.6+10-1ubuntu1~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.6+10-1ubuntu1~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.6+10-1ubuntu1~18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u242-b08-0ubuntu3~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u242-b08-0ubuntu3~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u242-b08-0ubuntu3~18.04", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u242-b08-0ubuntu3~18.04", rls: "UBUNTU18.04 LTS" ) )){
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
}
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u242-b08-0ubuntu3~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u242-b08-0ubuntu3~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u242-b08-0ubuntu3~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-jamvm", ver: "8u242-b08-0ubuntu3~16.04", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u242-b08-0ubuntu3~16.04", rls: "UBUNTU16.04 LTS" ) )){
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
}
exit( 0 );

