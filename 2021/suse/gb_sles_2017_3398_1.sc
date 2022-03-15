if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.3398.1" );
	script_cve_id( "CVE-2017-1000410", "CVE-2017-11600", "CVE-2017-12193", "CVE-2017-15115", "CVE-2017-16528", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-7482", "CVE-2017-8824" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 18:28:00 +0000 (Wed, 08 May 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:3398-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:3398-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20173398-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:3398-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.103 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2017-1000410: The Linux kernel was affected by an information lea
 that lies in the processing of incoming L2CAP commands - ConfigRequest,
 and ConfigResponse messages. (bnc#1070535).
- CVE-2017-11600: net/xfrm/xfrm_policy.c in the Linux kernel did not
 ensure that the dir value of xfrm_userpolicy_id is XFRM_POLICY_MAX or
 less, which allowed local users to cause a denial of service
 (out-of-bounds access) or possibly have unspecified other impact via an
 XFRM_MSG_MIGRATE xfrm Netlink message (bnc#1050231).
- CVE-2017-12193: The assoc_array_insert_into_terminal_node function in
 lib/assoc_array.c in the Linux kernel mishandled node splitting, which
 allowed local users to cause a denial of service (NULL pointer
 dereference and panic) via a crafted application, as demonstrated by the
 keyring key type, and key addition and link creation operations
 (bnc#1066192).
- CVE-2017-15115: The sctp_do_peeloff function in net/sctp/socket.c in the
 Linux kernel did not check whether the intended netns is used in a
 peel-off action, which allowed local users to cause a denial of service
 (use-after-free and system crash) or possibly have unspecified other
 impact via crafted system calls (bnc#1068671).
- CVE-2017-16528: sound/core/seq_device.c in the Linux kernel allowed
 local users to cause a denial of service (snd_rawmidi_dev_seq_free
 use-after-free and system crash) or possibly have unspecified other
 impact via a crafted USB device (bnc#1066629).
- CVE-2017-16536: The cx231xx_usb_probe function in
 drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux kernel allowed
 local users to cause a denial of service (NULL pointer dereference and
 system crash) or possibly have unspecified other impact via a crafted
 USB device (bnc#1066606).
- CVE-2017-16537: The imon_probe function in drivers/media/rc/imon.c in
 the Linux kernel allowed local users to cause a denial of service (NULL
 pointer dereference and system crash) or possibly have unspecified other
 impact via a crafted USB device (bnc#1066573).
- CVE-2017-16645: The ims_pcu_get_cdc_union_desc function in
 drivers/input/misc/ims-pcu.c in the Linux kernel allowed local users to
 cause a denial of service (ims_pcu_parse_cdc_data out-of-bounds read and
 system crash) or possibly have unspecified other impact via a crafted
 USB device (bnc#1067132).
- CVE-2017-16646: drivers/media/usb/dvb-usb/dib0700_devices.c in the Linux
 kernel allowed local users to cause a denial of service (BUG and system
 crash) or possibly have unspecified other impact via a crafted USB
 device (bnc#1067105).
- CVE-2017-16994: The walk_hugetlb_range function in mm/pagewalk.c in the
 Linux kernel mishandled holes in hugetlb ranges, which allowed local
 users to obtain sensitive information from uninitialized ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Container as a Service Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Live Patching 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.103~6.33.1", rls: "SLES12.0SP3" ) )){
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

