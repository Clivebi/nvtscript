if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842755" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-17 16:24:30 +0200 (Tue, 17 May 2016)" );
	script_cve_id( "CVE-2016-4557", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3672", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-3955" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-raspi2 USN-2965-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-raspi2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jann Horn discovered that the extended
  Berkeley Packet Filter (eBPF) implementation in the Linux kernel did not
  properly reference count file descriptors, leading to a use-after-free. A
  local unprivileged attacker could use this to gain administrative privileges.
  (CVE-2016-4557)

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

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  Linux kernel's USB driver for Digi AccelePort serial converters did not
  properly validate USB device descriptors. An attacker with physical access
  could use this to cause a denial of service (system crash). (CVE-2016-3140)

  It was discovered that the IPv4 implementation in the Linux kernel did not
  perform the destruction of inet device objects properly. An attacker in a
  guest OS could use this to cause a denial of service (networking  ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "linux-raspi2 on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2965-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2965-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1010-raspi2", ver: "4.4.0-1010.12", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

