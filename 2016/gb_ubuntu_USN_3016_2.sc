if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842809" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-28 05:25:19 +0200 (Tue, 28 Jun 2016)" );
	script_cve_id( "CVE-2016-4997", "CVE-2016-4482", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4913", "CVE-2016-4951", "CVE-2016-4998" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-raspi2 USN-3016-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-raspi2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jesse Hertz and Tim Newsham discovered that
  the Linux netfilter implementation did not correctly perform validation when
  handling 32 bit compatibility IPT_SO_SET_REPLACE events on 64 bit platforms. A
  local unprivileged attacker could use this to cause a denial of service (system
  crash) or execute arbitrary code with administrative privileges.
  (CVE-2016-4997)

Kangjie Lu discovered an information leak in the core USB implementation in
the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4482)

Kangjie Lu discovered an information leak in the timer handling
implementation in the Advanced Linux Sound Architecture (ALSA) subsystem of
the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4569, CVE-2016-4578)

Kangjie Lu discovered an information leak in the X.25 Call Request handling
in the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4580)

It was discovered that an information leak exists in the Rock Ridge
implementation in the Linux kernel. A local attacker who is able to mount a
malicious iso9660 file system image could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2016-4913)

Baozeng Ding discovered that the Transparent Inter-process Communication
(TIPC) implementation in the Linux kernel did not verify socket existence
before use in some situations. A local attacker could use this to cause a
denial of service (system crash). (CVE-2016-4951)

Jesse Hertz and Tim Newsham discovered that the Linux netfilter
implementation did not correctly perform validation when handling
IPT_SO_SET_REPLACE events. A local unprivileged attacker could use this to
cause a denial of service (system crash) or obtain potentially sensitive
information from kernel memory. (CVE-2016-4998)" );
	script_tag( name: "affected", value: "linux-raspi2 on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3016-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3016-2/" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-4.4.0-1016-raspi2", ver: "4.4.0-1016.22", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

