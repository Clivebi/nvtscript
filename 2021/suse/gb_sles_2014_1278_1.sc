if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1278.1" );
	script_cve_id( "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3461" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 14:39:00 +0000 (Mon, 02 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1278-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1278-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141278-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2014:1278-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "kvm has been updated to fix issues in the embedded qemu:

 *

 CVE-2014-0223: An integer overflow flaw was found in the QEMU block driver for QCOW version 1 disk images. A user able to alter the QEMU disk image files loaded by a guest could have used this flaw to corrupt QEMU process memory on the host, which could potentially have resulted in arbitrary code execution on the host with the privileges
 of the QEMU process.

 *

 CVE-2014-3461: A user able to alter the savevm data (either on the disk or over the wire during migration) could have used this flaw to corrupt QEMU process memory on the (destination) host, which could have potentially resulted in arbitrary code execution on the host with the privileges of the QEMU process.

 *

 CVE-2014-0222: An integer overflow flaw was found in the QEMU block driver for QCOW version 1 disk images. A user able to alter the QEMU disk image files loaded by a guest could have used this flaw to corrupt QEMU process memory on the host, which could have potentially resulted in arbitrary code execution on the host with the privileges
 of the QEMU process.

Non-security bugs fixed:

 * Fix exceeding IRQ routes that could have caused freezes of guests.
 (bnc#876842)
 * Fix CPUID emulation bugs that may have broken Windows guests with
 newer -cpu types (bnc#886535)

Security Issues:

 * CVE-2014-0222
 * CVE-2014-0223
 * CVE-2014-3461" );
	script_tag( name: "affected", value: "'kvm' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kvm", rpm: "kvm~1.4.2~0.17.1", rls: "SLES11.0SP3" ) )){
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

