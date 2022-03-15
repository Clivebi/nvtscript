if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842736" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-10 05:20:35 +0200 (Tue, 10 May 2016)" );
	script_cve_id( "CVE-2015-7515", "CVE-2016-0821", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3689" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:26:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-wily USN-2971-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-wily'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2971-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 15.10. This update provides the corresponding updates
  for the Linux Hardware
  Enablement (HWE) kernel from Ubuntu 15.10 for Ubuntu 14.04 LTS.

  Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in the
  Linux kernel did not properly sanity check the endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2015-7515)

  Zach Riggle discovered that the Linux kernel's list poison feature did not
  take into account the mmap_min_addr value. A local attacker could use this
  to bypass the kernel's poison-pointer protection mechanism while attempting
  to exploit an existing kernel vulnerability. (CVE-2016-0821)

  Ralf Spenneberg discovered that the USB sound subsystem in the Linux kernel
  did not properly validate USB device descriptors. An attacker with physical
  access could use this to cause a denial of service (system crash).
  (CVE-2016-2184)

  Ralf Spenneberg discovered that the ATI Wonder Remote II USB driver in the
  Linux kernel did not properly validate USB device descriptors. An attacker
  with physical access could use this to cause a denial of service (system
  crash). (CVE-2016-2185)

  Ralf Spenneberg discovered that the PowerMate USB driver in the Linux
  kernel did not properly validate USB device descriptors. An attacker with
  physical access could use this to cause a denial of service (system crash).
  (CVE-2016-2186)

  Ralf Spenneberg discovered that the I/O-Warrior USB device driver in the
  Linux kernel did not properly validate USB device descriptors. An attacker
  with physical access could use this to cause a denial of service (system
  crash). (CVE-2016-2188)

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  MCT USB RS232 Converter device driver in the Linux kernel did not properly
  validate USB device descriptors. An attacker with physical access could use
  this to cause a denial of service (system crash). (CVE-2016-3136)

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  Cypress M8 USB device driver in the Linux kernel did not properly validate
  USB device descriptors. An attacker with physical access could use this to
  cause a denial of service (system crash). (CVE-2016-3137)

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  USB abstract device control driver for modems and ISDN adapters did not
  validate endpoint descriptors. An attacker with physical access could use
  this to cause a denial of service (system crash). (CVE-2016-3138)

  Sergej Schumilo, Hendrik Schwartke, and Ralf  ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "linux-lts-wily on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2971-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2971-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-36-generic", ver: "4.2.0-36.41~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-36-generic-lpae", ver: "4.2.0-36.41~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-36-lowlatency", ver: "4.2.0-36.41~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-36-powerpc-e500mc", ver: "4.2.0-36.41~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-36-powerpc-smp", ver: "4.2.0-36.41~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-36-powerpc64-emb", ver: "4.2.0-36.41~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-36-powerpc64-smp", ver: "4.2.0-36.41~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

