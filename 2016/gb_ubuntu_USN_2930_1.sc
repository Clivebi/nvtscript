if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842691" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-15 06:36:46 +0100 (Tue, 15 Mar 2016)" );
	script_cve_id( "CVE-2016-3134", "CVE-2016-3135", "CVE-2015-7566", "CVE-2015-8767", "CVE-2016-0723", "CVE-2016-2384", "CVE-2016-2782" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2930-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Ben Hawkes discovered that the Linux
  netfilter implementation did not correctly perform validation when handling
  IPT_SO_SET_REPLACE events. A local unprivileged attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary code
  with administrative privileges. (CVE-2016-3134)

  Ben Hawkes discovered an integer overflow in the Linux netfilter
  implementation. On systems running 32 bit kernels, a local unprivileged
  attacker could use this to cause a denial of service (system crash) or
  possibly execute arbitrary code with administrative privileges.
  (CVE-2016-3135)

  Ralf Spenneberg discovered that the USB driver for Clie devices in the
  Linux kernel did not properly sanity check the endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2015-7566)

  It was discovered that a race condition existed when handling heartbeat-
  timeout events in the SCTP implementation of the Linux kernel. A remote
  attacker could use this to cause a denial of service. (CVE-2015-8767)

  It was discovered that a race condition existed in the ioctl handler for
  the TTY driver in the Linux kernel. A local attacker could use this to
  cause a denial of service (system crash) or expose sensitive information.
  (CVE-2016-0723)

  Andrey Konovalov discovered that the ALSA USB MIDI driver incorrectly
  performed a double-free. A local attacker with physical access could use
  this to cause a denial of service (system crash) or possibly execute
  arbitrary code with administrative privileges. (CVE-2016-2384)

  Ralf Spenneberg discovered that the USB driver for Treo devices in the
  Linux kernel did not properly sanity check the endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2016-2782)" );
	script_tag( name: "affected", value: "linux on Ubuntu 15.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2930-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2930-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU15\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-34-generic", ver: "4.2.0-34.39", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-34-generic-lpae", ver: "4.2.0-34.39", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-34-lowlatency", ver: "4.2.0-34.39", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-34-powerpc-e500mc", ver: "4.2.0-34.39", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-34-powerpc-smp", ver: "4.2.0-34.39", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-34-powerpc64-emb", ver: "4.2.0-34.39", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-4.2.0-34-powerpc64-smp", ver: "4.2.0-34.39", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

