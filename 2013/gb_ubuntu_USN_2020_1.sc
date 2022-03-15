if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841618" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-11-18 15:45:27 +0530 (Mon, 18 Nov 2013)" );
	script_cve_id( "CVE-2013-0343", "CVE-2013-2147", "CVE-2013-2889", "CVE-2013-2893", "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2897", "CVE-2013-4343" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for linux-lts-raring USN-2020-1" );
	script_tag( name: "affected", value: "linux-lts-raring on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "An information leak was discovered in the handling of ICMPv6
Router Advertisement (RA) messages in the Linux kernel's IPv6 network stack. A
remote attacker could exploit this flaw to cause a denial of service
(excessive retries and address-generation outage), and consequently obtain
sensitive information. (CVE-2013-0343)

Dan Carpenter discovered an information leak in the HP Smart Array and
Compaq SMART2 disk-array driver in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-2147)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem
when CONFIG_HID_ZEROPLUS is enabled. A physically proximate attacker could
leverage this flaw to cause a denial of service via a specially crafted
device. (CVE-2013-2889)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when any of CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF are enabled. A physcially
proximate attacker can leverage this flaw to cause a denial of service vias
a specially crafted device. (CVE-2013-2893)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel when CONFIG_HID_LENOVO_TPKBD is enabled. A physically
proximate attacker could exploit this flaw to cause a denial of service via
a specially crafted device. (CVE-2013-2894)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LOGITECH_DJ is enabled. A
physically proximate attacker could cause a denial of service (OOPS) or
obtain sensitive information from kernel memory via a specially crafted
device. (CVE-2013-2895)

Kees Cook discovered yet another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_MULTITOUCH is enabled. A
physically proximate attacker could leverage this flaw to cause a denial of
service (OOPS) via a specially crafted device. (CVE-2013-2897)

Wannes Rombouts reported a vulnerability in the networking tuntap interface
of the Linux kernel. A local user with the CAP_NET_ADMIN capability could
leverage this flaw to gain full admin privileges. (CVE-2013-4343)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2020-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2020-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-raring'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-3.8.0-33-generic", ver: "3.8.0-33.48~precise1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

