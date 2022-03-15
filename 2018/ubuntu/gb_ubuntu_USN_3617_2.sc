if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843492" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-04 08:30:51 +0200 (Wed, 04 Apr 2018)" );
	script_cve_id( "CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-15129", "CVE-2017-16532", "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16647", "CVE-2017-16649", "CVE-2017-16650", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17450", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-18204", "CVE-2018-1000026", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5344" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-24 10:29:00 +0000 (Fri, 24 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-gcp USN-3617-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-gcp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3617-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.10. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu
  16.04 LTS. It was discovered that a race condition leading to a use-after-free
  vulnerability existed in the ALSA PCM subsystem of the Linux kernel. A local
  attacker could use this to cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2017-0861) It was discovered that the KVM
  implementation in the Linux kernel allowed passthrough of the diagnostic I/O
  port 0x80. An attacker in a guest VM could use this to cause a denial of service
  (system crash) in the host OS. (CVE-2017-1000407) It was discovered that a
  use-after-free vulnerability existed in the network namespaces implementation in
  the Linux kernel. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2017-15129) Andrey
  Konovalov discovered that the usbtest device driver in the Linux kernel did not
  properly validate endpoint metadata. A physically proximate attacker could use
  this to cause a denial of service (system crash). (CVE-2017-16532) Andrey
  Konovalov discovered that the SoundGraph iMON USB driver in the Linux kernel did
  not properly validate device metadata. A physically proximate attacker could use
  this to cause a denial of service (system crash). (CVE-2017-16537) Andrey
  Konovalov discovered that the IMS Passenger Control Unit USB driver in the Linux
  kernel did not properly validate device descriptors. A physically proximate
  attacker could use this to cause a denial of service (system crash).
  (CVE-2017-16645) Andrey Konovalov discovered that the DiBcom DiB0700 USB DVB
  driver in the Linux kernel did not properly handle detach events. A physically
  proximate attacker could use this to cause a denial of service (system crash).
  (CVE-2017-16646) Andrey Konovalov discovered that the ASIX Ethernet USB driver
  in the Linux kernel did not properly handle suspend and resume events. A
  physically proximate attacker could use this to cause a denial of service
  (system crash). (CVE-2017-16647) Andrey Konovalov discovered that the CDC USB
  Ethernet driver did not properly validate device descriptors. A physically
  proximate attacker could use this to cause a denial of service (system crash).
  (CVE-2017-16649) Andrey Konovalov discovered that the QMI WWAN USB driver did
  not properly validate device descriptors. A physically proximate attacker could
  use this to cause a denial of service (system crash). (CVE-2017-16650) It was
  discovered that the HugeTLB c ... Description truncated, for more information
  please check the Reference URL" );
	script_tag( name: "affected", value: "linux-gcp on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3617-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3617-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1012-gcp", ver: "4.13.0-1012.16", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-1022-oem", ver: "4.13.0-1022.24", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-38-generic", ver: "4.13.0-38.43~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-38-generic-lpae", ver: "4.13.0-38.43~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.13.0-38-lowlatency", ver: "4.13.0-38.43~16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "4.13.0.1012.14", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.13.0.38.57", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.13.0.38.57", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.13.0.1012.14", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.13.0.38.57", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-oem", ver: "4.13.0.1022.26", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

