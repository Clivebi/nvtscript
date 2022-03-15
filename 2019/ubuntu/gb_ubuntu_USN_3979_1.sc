if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844004" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2018-12130", "CVE-2018-12127", "CVE-2018-12126", "CVE-2019-11091", "CVE-2019-11683", "CVE-2019-1999", "CVE-2019-3874", "CVE-2019-3882", "CVE-2019-3887", "CVE-2019-9500", "CVE-2019-9503" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-15 02:02:39 +0000 (Wed, 15 May 2019)" );
	script_name( "Ubuntu Update for linux USN-3979-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.04" );
	script_xref( name: "USN", value: "3979-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3979-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-3979-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Giorgi Maisuradze, Dan
Horea Lutas, Andrei Lutas, Volodymyr Pikhur, Stephan van Schaik, Alyssa
Milburn, Sebastian sterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos,
Cristiano Giuffrida, Moritz Lipp, Michael Schwarz, and Daniel Gruss
discovered that memory previously stored in microarchitectural fill buffers
of an Intel CPU core may be exposed to a malicious process that is
executing on the same CPU core. A local attacker could use this to expose
sensitive information. (CVE-2018-12130)

Brandon Falk, Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Stephan
van Schaik, Alyssa Milburn, Sebastian sterlund, Pietro Frigo, Kaveh
Razavi, Herbert Bos, and Cristiano Giuffrida discovered that memory
previously stored in microarchitectural load ports of an Intel CPU core may
be exposed to a malicious process that is executing on the same CPU core. A
local attacker could use this to expose sensitive information.
(CVE-2018-12127)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Marina Minkin, Daniel
Moghimi, Moritz Lipp, Michael Schwarz, Jo Van Bulck, Daniel Genkin, Daniel
Gruss, Berk Sunar, Frank Piessens, and Yuval Yarom discovered that memory
previously stored in microarchitectural store buffers of an Intel CPU core
may be exposed to a malicious process that is executing on the same CPU
core. A local attacker could use this to expose sensitive information.
(CVE-2018-12126)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Volodrmyr Pikhur,
Moritz Lipp, Michael Schwarz, Daniel Gruss, Stephan van Schaik, Alyssa
Milburn, Sebastian sterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos, and
Cristiano Giuffrida discovered that uncacheable memory previously stored in
microarchitectural buffers of an Intel CPU core may be exposed to a
malicious process that is executing on the same CPU core. A local attacker
could use this to expose sensitive information. (CVE-2019-11091)

It was discovered that the IPv4 generic receive offload (GRO) for UDP
implementation in the Linux kernel did not properly handle padded packets.
A remote attacker could use this to cause a denial of service (system
crash). (CVE-2019-11683)

It was discovered that a race condition existed in the Binder IPC driver
for the Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2019-1999)

Matteo Croce, Natale Vinto, and Andrea Spagnolo discovered that the cgroups
subsystem of the Linux kernel did not properly account for SCTP socket
buffers. A local attacker could use this to cause a denial of service
(sys ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 19.04." );
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1006-aws", ver: "5.0.0-1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1006-azure", ver: "5.0.0-1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1006-gcp", ver: "5.0.0-1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1006-kvm", ver: "5.0.0-1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-1008-raspi2", ver: "5.0.0-1008.8", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-15-generic", ver: "5.0.0-15.16", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-15-generic-lpae", ver: "5.0.0-15.16", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.0.0-15-lowlatency", ver: "5.0.0-15.16", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws", ver: "5.0.0.1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure", ver: "5.0.0.1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "5.0.0.1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "5.0.0.15.16", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "5.0.0.15.16", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke", ver: "5.0.0.1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "5.0.0.1006.6", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "5.0.0.15.16", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-raspi2", ver: "5.0.0.1008.5", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "5.0.0.15.16", rls: "UBUNTU19.04" ) )){
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

