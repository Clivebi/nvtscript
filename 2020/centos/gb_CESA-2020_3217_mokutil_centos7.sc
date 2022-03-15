if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883264" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309", "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-15705", "CVE-2020-15706", "CVE-2020-15707" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)" );
	script_tag( name: "creation_date", value: "2020-07-30 03:01:19 +0000 (Thu, 30 Jul 2020)" );
	script_name( "CentOS: Security Advisory for mokutil (CESA-2020:3217)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:3217" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-July/035783.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mokutil'
  package(s) announced via the CESA-2020:3217 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The grub2 packages provide version 2 of the Grand Unified Boot Loader
(GRUB), a highly configurable and customizable boot loader with modular
architecture. The packages support a variety of kernel formats, file
systems, computer architectures, and hardware devices.

The shim package contains a first-stage UEFI boot loader that handles
chaining to a trusted full boot loader under secure boot environments.

The fwupdate packages provide a service that allows session software to
update device firmware.

Security Fix(es):

  * grub2: Crafted grub.cfg file can lead to arbitrary code execution during
boot process (CVE-2020-10713)

  * grub2: grub_malloc does not validate allocation size allowing for
arithmetic overflow and subsequent heap-based buffer overflow
(CVE-2020-14308)

  * grub2: Integer overflow in grub_squash_read_symlink may lead to
heap-based buffer overflow (CVE-2020-14309)

  * grub2: Integer overflow read_section_as_string may lead to heap-based
buffer overflow (CVE-2020-14310)

  * grub2: Integer overflow in grub_ext2_read_link leads to heap-based buffer
overflow (CVE-2020-14311)

  * grub2: Fail kernel validation without shim protocol (CVE-2020-15705)

  * grub2: Use-after-free redefining a function whilst the same function is
already executing (CVE-2020-15706)

  * grub2: Integer overflow in initrd size handling (CVE-2020-15707)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * grub2 doesn't handle relative paths correctly for UEFI HTTP Boot
(BZ#1616395)

  * UEFI HTTP boot over IPv6 does not work (BZ#1732765)

Users of grub2 are advised to upgrade to these updated packages, which fix
these bugs." );
	script_tag( name: "affected", value: "'mokutil' package(s) on CentOS 7." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "mokutil", rpm: "mokutil~15~7.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shim-ia32", rpm: "shim-ia32~15~7.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shim-x64", rpm: "shim-x64~15~7.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shim-signed", rpm: "shim-signed~15~7.el7_9", rls: "CentOS7" ) )){
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

