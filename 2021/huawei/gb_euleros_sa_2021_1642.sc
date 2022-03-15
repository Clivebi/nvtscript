if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1642" );
	script_cve_id( "CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-0466", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14314", "CVE-2020-14385", "CVE-2020-14386", "CVE-2020-15437", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-26088", "CVE-2020-27068", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-27830", "CVE-2020-28915", "CVE-2020-28941", "CVE-2020-28974", "CVE-2020-29368", "CVE-2020-29371", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-8694" );
	script_tag( name: "creation_date", value: "2021-03-12 07:25:01 +0000 (Fri, 12 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-08 16:15:00 +0000 (Thu, 08 Apr 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-1642)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1642" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1642" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2021-1642 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In create_pinctrl of core.c, there is a possible out of bounds read due to a use after free. This could lead to local information disclosure with no additional execution privileges needed.(CVE-2020-0427)

NULL-ptr deref in the spk_ttyio_receive_buf2() function in spk_ttyio.c.(CVE-2020-27830)

In do_epoll_ctl and ep_loop_check_proc of eventpoll.c, there is a possible use after free due to a logic error. This could lead to local escalation of privilege with no additional execution privileges needed.(CVE-2020-0466)

In the nl80211_policy policy of nl80211.c, there is a possible out of bounds read due to a missing bounds check. This could lead to local information disclosure with System execution privileges needed.(CVE-2020-27068)

use-after-free read in sunkbd_reinit in drivers/input/keyboard/sunkbd.c.(CVE-2020-25669)

A flaw was found in the Linux kernels implementation of MIDI, where an attacker with a local account and the permissions to issue an ioctl commands to midi devices, could trigger a use-after-free. A write to this specific memory while freed and before use could cause the flow of execution to change and possibly allow for memory corruption or privilege escalation.(CVE-2020-27786)

An issue was discovered in romfs_dev_read in fs/romfs/storage.c in the Linux kernel before 5.8.4. Uninitialized memory leaks to userspace, aka CID-bcf85fcedfdd.(CVE-2020-29371)

A slab-out-of-bounds read in fbcon in the Linux kernel before 5.9.7 could be used by local attackers to read privileged information or potentially crash the kernel, aka CID-3c4e0dff2095. This occurs because KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for manipulations such as font height.(CVE-2020-28974)

A locking inconsistency issue was discovered in the tty subsystem of the Linux kernel through 5.9.13. drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may allow a read-after-free attack against TIOCGSID, aka CID-c8bcd9c5be24.(CVE-2020-29660)

A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13. drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.(CVE-2020-29661)

An issue was discovered in drivers/accessibility/speakup/spk_ttyio.c in the Linux kernel through 5.9.9. Local attackers on systems with the speakup driver could cause a local denial of service attack, aka CID-d41227544427. This occurs because of an invalid free when the line discipline is used more than once.(CVE-2020-28941)

A buffer over-read (at the framebuffer layer) in the fbcon code in the Linux kernel before 5.8.15 could be used by local attackers to read kernel memory, aka CID-6735b4632def.(CVE-2020-28915)

A flaw in the way reply ICMP packets are limited in the Linux kernel functionality was found that allows to quickly scan open UDP ports. This flaw allows an off-path remote user to effectively bypassing source port UDP randomization. The highest ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'kernel' package(s) on Huawei EulerOS Virtualization release 2.9.0." );
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
if(release == "EULEROSVIRT-2.9.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.18.0~147.5.1.2.h314.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~4.18.0~147.5.1.2.h314.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~4.18.0~147.5.1.2.h314.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-perf", rpm: "python3-perf~4.18.0~147.5.1.2.h314.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
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

