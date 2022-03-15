if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842816" );
	script_version( "2021-09-20T11:27:24+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:27:24 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-28 05:26:20 +0200 (Tue, 28 Jun 2016)" );
	script_cve_id( "CVE-2016-3951", "CVE-2016-4482", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4805", "CVE-2016-4913" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-3021-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Andrey Konovalov discovered that the CDC
  Network Control Model USB driver in the Linux kernel did not cancel work events
  queued if a later error occurred, resulting in a use-after-free. An attacker with
  physical access could use this to cause a denial of service (system crash).
  (CVE-2016-3951)

Kangjie Lu discovered an information leak in the core USB implementation in
the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4482)

Jann Horn discovered that the InfiniBand interfaces within the Linux kernel
could be coerced into overwriting kernel memory. A local unprivileged
attacker could use this to possibly gain administrative privileges on
systems where InifiniBand related kernel modules are loaded.
(CVE-2016-4565)

Kangjie Lu discovered an information leak in the timer handling
implementation in the Advanced Linux Sound Architecture (ALSA) subsystem of
the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4569, CVE-2016-4578)

Kangjie Lu discovered an information leak in the X.25 Call Request handling
in the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4580)

Baozeng Ding discovered a use-after-free issue in the generic PPP layer in
the Linux kernel. A local attacker could use this to cause a denial of
service (system crash). (CVE-2016-4805)

It was discovered that an information leak exists in the Rock Ridge
implementation in the Linux kernel. A local attacker who is able to mount a
malicious iso9660 file system image could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2016-4913)" );
	script_tag( name: "affected", value: "linux on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3021-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3021-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-105-generic", ver: "3.2.0-105.146", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-105-generic-pae", ver: "3.2.0-105.146", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-105-highbank", ver: "3.2.0-105.146", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-105-omap", ver: "3.2.0-105.146", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-105-powerpc-smp", ver: "3.2.0-105.146", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-105-powerpc64-smp", ver: "3.2.0-105.146", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-105-virtual", ver: "3.2.0-105.146", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

